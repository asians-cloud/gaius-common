'''
Created on Oct 30, 2021

'''
import django, re, logging, ssl , subprocess
from abc import ABC
import requests
import dns.resolver

from django import forms

from django.db import models

from django.core.validators import RegexValidator

from requests.exceptions import SSLError, ConnectTimeout



def _domain_name_validator():

    ul = '\u00a1-\uffff'  # unicode letters range (must not be a raw string)

    # IP patterns
    ipv4_re = r'(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}'
    ipv6_re = r'\[[0-9a-f:\.]+\]'  # (simple regex, validated later)

    # Host patterns
    hostname_re = r'[a-z' + ul + \
        r'0-9](?:[a-z' + ul + r'0-9-]{0,61}[a-z' + ul + r'0-9])?'
    # Max length for domain name labels is 63 characters per RFC 1034 sec. 3.1
    domain_re = r'(?:\.(?!-)[a-z' + ul + r'0-9-]{1,63}(?<!-))*'
    tld_re = (
        r'\.'  # dot
        r'(?!-)'  # can't start with a dash
        r'(?:[a-z' + ul + '-]{2,63}'  # domain label
        r'|xn--[a-z0-9]{1,59})'  # or punycode label
        r'(?<!-)'  # can't end with a dash
        r'\.?'  # may have a trailing dot
        r'/?'
    )
    host_re = '(' + hostname_re + domain_re + tld_re + ')'
    regex = (
        r'(?:' + ipv4_re + '|' + ipv6_re + '|' + host_re + ')'
        r'(?::\d{2,5})?'  # port
        r'\Z')
    return RegexValidator(regex, message='Enter a valid Domain (Not a URL)', code='invalid_domain')

domain_name_validator = _domain_name_validator()



class DomainNameFormField(forms.CharField):
    description = 'Domain name form field'
    default_validators = [domain_name_validator, ]

    def __init__(self,  *args, **kwargs):
        super(DomainNameFormField, self).__init__(*args, **kwargs)



class DomainNameField(models.CharField):
    description = 'Domain name field'
    empty_strings_allowed = False
    default_validators = [domain_name_validator, ]

    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = kwargs.get('max_length', 72)
        super(DomainNameField, self).__init__(*args, **kwargs)

    def formfield(self, **kwargs):
        defaults = {'form_class': DomainNameFormField}
        defaults.update(kwargs)
        return super(DomainNameField, self).formfield(**defaults)

    def to_python(self, value):
        def convert(val):
            if val is None:
                return val
            domain_name_validator(value)
            pattern = re.compile(r"https?://(www\.)?")
            result = pattern.sub('', val).strip().strip('/')
            return result
        if isinstance(value, str) or value is None:
            return convert(value)
        return convert(str(value))

class Cname:
    def __init__(self, value):
        self.value = value

    @property
    def zone(self):
        return ".".join(self.value.split(".")[-2:])

    @property
    def subscription(self):
        return self.value.split(".")[-3]

    @property
    def domain(self):
        d = self.value.split(".")[-4]
        return d.replace("--", "-").replace("-", ".")

class CnameField(DomainNameField):
    @property
    def zone(self):
        return Cname(self.value).zone

    @property
    def subscription(self):
        return Cname(self.value).subscription

    @property
    def domain(self):
        return Cname(self.value).domain




class DomainChecker(ABC):

    def __init__(self, name, cname, aliases=[], **kwargs):
        self.domain = name
        self.cname = cname
        self.aliases = aliases

    def check(self, steps, aliases=[], continue_on_false=False):
        status = { step: (False, "") for step in steps }
        for step in steps:
            check_method = getattr(self, step)
            try:
                checkrs = check_method()
                checkmsg = "OK" if checkrs else "Failed"
            except Exception as e:
                checkrs = False
                logging.info(e)
                checkmsg = str(e)

            status[step] = (checkrs, checkmsg)

            if checkrs == False and continue_on_false == False:
                print("failed on %s %s" % ( step, checkrs))
                break

        return status

    def dns_cdn_challenge(self, needle, **_kwargs):
        if self.domain.count('.') == 1:
            root_domain = self.domain
        else:
            root_domain = '.'.join(self.domain.split('.')[1:])

        print(root_domain)
        try:
            a = dns.resolver.query("_cdn-challenge."  + root_domain, rdtype=dns.rdatatype.RdataType.TXT)
        except dns.exception.DNSException as _e:
            raise RuntimeError('DNS query failed')

        res = "%s" % a.response

        if re.search(r'TXT\s+"%s"' % needle, res) != None:
            return True

        return False

    def cname_query(self, **_kwargs):
        return all([
                len(dns.resolver.query(self.cname)) > 0
            ])

    def cname_visit(self, **_kwargs):
        try:
            r = requests.get("http://%s/ok" % self.cname, timeout=2)
        except requests.exceptions.RequestException as _e:
            raise RuntimeError('CName visit failed')

        if r.status_code != 200 or r.text != "OK":
            raise RuntimeError('CName visit failed')

        return True

    def domain_setup(self, domain):
        return all([
            self.init(domain),
            self.cname_visit(domain),
            self.source_cname(),
            ])

    def source_cname(self, **_kwargs):

        try:
            a = dns.resolver.query(self.domain)
        except dns.exception.DNSException as _e:
            raise RuntimeError('DNS query failed')

        res = "%s" % a.response
        if re.search(r"CNAME.+%s" % self.cname[0:10], res) != None:
            return True
        elif self.domain.count('.') == 1 and a.rdtype == dns.rdatatype.A: #Naked domain
            try:
                ip = a.response.answer[0][0].address
                v = requests.get("http://%s/ok" % ip)
                if v.text == "OK":
                    return True
            except Exception:
                logging.warn('Try nake domain check failed')

        raise RuntimeError('CName not found')

    def source_visit_https(self, domain, cname, source=None):
        logging.info("source_visit_https")
        try:
            cmnd = [
                "curl", "-s", "--max-time", "5", "-I",
                'https://%s/' % domain,
                "--resolve",
                "%s:%d:%s" % (domain, source['port'], domain )
            ]
            tryhttps = subprocess.run(cmnd, capture_output=True)

            if tryhttps.returncode > 0:
                raise RuntimeError('Source https checked failed: %s' % (tryhttps.returncode, ) )

        except SSLError as e:
            logging.info(e)
            raise RuntimeError('SSL Error2')
        except ConnectTimeout as e:
            logging.info(e)
            raise RuntimeError('Connect Timeout')
        except ConnectionError as e:
            logging.info(e)
            raise RuntimeError('Connect Error')
        except Exception as e:
            logging.info(e)
            raise e

        return True

    def source_visit(self, domain, source):
        #config = domain.sourceConfigParsed

        try:
            if source['source_scheme'] == 'https':
                if domain.sslConfigEnabled == False:
                    raise RuntimeError('HTTPS is required')

                return self.source_visit_https(domain)

            url = '%(scheme)s://%(hostname)s:%(port)s' % source

            r = requests.get(url, headers={'Host': "%s" % domain }, allow_redirects = False, timeout=2)

            if r.status_code == 301 or r.status_code == 302:
                if r.headers['Location'].startswith("https://%s" % domain):
                    source['scheme'] = 'https'
                    source['port'] = 443
                    checkRs = self.source_visit_https(domain, source)
                    if checkRs:
                        full_url = '%(scheme)s://%(hostname)s:%(port)s' % source
                        domain.sourceConfig['full_url'] = full_url
                        domain.save()

                    if domain.sslConfigEnabled == False:
                        raise RuntimeError('HTTPS is required')

                    return checkRs
                elif r.headers['Location'].startswith("http"):
                    r = requests.get(r.headers['Location'], timeout=2)
                else:
                    url2 = '%s%s' % ( url, r.headers['Location'])
                    r = requests.get(url2, headers={'Host': "%s" % domain.name }, allow_redirects = True, timeout=2)
        except SSLError as e:
            logging.info(e)
            raise RuntimeError('SSL Error')
        except ConnectTimeout as e:
            logging.info(e)
            raise RuntimeError('Connect Timeout')
        except ConnectionError as e:
            logging.info(e)
            raise RuntimeError('Connect Error')
        except Exception as e:
            logging.info(e)
            raise e

        return True

#         return all([
#             r.status_code > 200,
#             len(r.content.decode("UTF-8").strip()) > 100  #TODO, check the header from proxy
#             ])

    def site_visit(self, domain, scheme='http', check_url=None):
        if check_url:
            check_url = "%s://%s/" % (scheme, domain)
        try:
            _r = requests.get(check_url, verify=ssl.CERT_NONE, timeout=5)
        except SSLError as e:
            raise RuntimeError('SSL Error3')
        except Exception as e:
            raise e  #RuntimeError('Check URL error')

        return True

#         return all([
#             r.status_code == 200,
#             len(r.content.decode("UTF-8").strip()) > 100  #TODO, check the header from proxy
#             ])

    def source_setup(self, domain):
        return all([
            self.source_cname(domain),
            self.source_visit(domain),
            ])

    def ssl_config(self, domain):
        return all([
            self.sslConfigEnabled,
            #Add more
            ])

    def ssl_visit(self, domain):
        try:
            _r = requests.get("https://%s/" % domain.name, verify=ssl.CERT_NONE, timeout=2)
        except SSLError as e:
            raise RuntimeError('SSL Error')
        except Exception as e:
            raise e  #RuntimeError('Check URL error')

        return True

#         return all([
#             r.status_code == 200,
#             len(r.content.decode("UTF-8").strip()) > 100 #TODO, check the header from proxy
#             ])

    def ssl_setup(self, domain):
        return all([
            self.ssl_config(domain),
            self.ssl_visit(domain),
            ])


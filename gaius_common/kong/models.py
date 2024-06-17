import uuid, functools
from django.db import models
from django.contrib.postgres.fields import ArrayField
from fcm_django.models import FCMDevice

KONG_ROUTE = 1
KONG_SERVICE = 2
KONG_UPSTREAM = 3
KONG_CHOICES = (
    (KONG_ROUTE, 'Kong Route'),
    (KONG_SERVICE, 'Kong Service'),
    (KONG_UPSTREAM, 'Kong Upstream')
)

class Acls(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    consumer = models.ForeignKey('Consumers', models.DO_NOTHING, blank=True, null=True)
    group = models.TextField(blank=True, null=True)
    cache_key = models.TextField(unique=True, blank=True, null=True)
    tags = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    ws = models.ForeignKey('Workspaces', models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'acls'
        unique_together = (('id', 'ws'),)

    def save(self, *args, **kwargs):

        # First Need to store ws_id in workspaces table
        self.ws = Workspaces.objects.get()

        super(Acls, self).save(*args, **kwargs)


class AcmeStorage(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    key = models.TextField(unique=True, blank=True, null=True)
    value = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    ttl = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'acme_storage'


class BasicauthCredentials(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    consumer = models.ForeignKey('Consumers', models.DO_NOTHING, blank=True, null=True)
    username = models.TextField(blank=True, null=True)
    password = models.TextField(blank=True, null=True)
    tags = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    ws = models.ForeignKey('Workspaces', models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'basicauth_credentials'
        unique_together = (('id', 'ws'), ('ws', 'username'),)

    def save(self, *args, **kwargs):

        # First Need to store ws_id in workspaces table
        self.ws = Workspaces.objects.get()

        super(BasicauthCredentials, self).save(*args, **kwargs)


class CaCertificates(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    cert = models.TextField()
    tags = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    cert_digest = models.TextField(unique=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'ca_certificates'


class Certificates(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    cert = models.TextField(blank=True, null=True)
    key = models.TextField(blank=True, null=True)
    tags = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    ws = models.ForeignKey('Workspaces', models.DO_NOTHING, blank=True, null=True, related_name='certificates')
    cert_alt = models.TextField(blank=True, null=True)
    key_alt = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'certificates'
        unique_together = (('id', 'ws'),)

    def save(self, *args, **kwargs):

        # First Need to store ws_id in workspaces table
        self.ws = Workspaces.objects.get()

        super(Certificates, self).save(*args, **kwargs)

    def __str__(self):
        return str(self.id)

    @property
    def snis(self):
        queryset = self.snis_set.all()
        return [item.name for item in queryset]

    def tags_to_dict(self):
        tags = {}
        if tags:
            for tag in self.tags:
                key, value = tag.replace('"', "").split("=")
                tags[key] = value
        return tags

    @property
    def cname(self):
        tags = self.tags_to_dict()
        return tags.get("cname", '')

    @property
    def owner(self):
        tags = self.tags_to_dict()
        return tags.get('owner', '')


class ClusterEvents(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    node_id = models.UUIDField()
    at = models.DateTimeField()
    nbf = models.DateTimeField(blank=True, null=True)
    expire_at = models.DateTimeField()
    channel = models.TextField(blank=True, null=True)
    data = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'cluster_events'


class ClusteringDataPlanes(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    hostname = models.TextField()
    ip = models.TextField()
    last_seen = models.DateTimeField(blank=True, null=True)
    config_hash = models.TextField()
    ttl = models.DateTimeField(blank=True, null=True)
    version = models.TextField(blank=True, null=True)
    sync_status = models.TextField()

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'clustering_data_planes'


class Consumers(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    username = models.TextField(blank=True, null=True)
    custom_id = models.TextField(blank=True, null=True)
    tags = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    ws = models.ForeignKey('Workspaces', models.DO_NOTHING, blank=True, null=True, related_name='consumers')

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'consumers'
        unique_together = (('id', 'ws'), ('ws', 'username'), ('ws', 'custom_id'),)

    def save(self, *args, **kwargs):

        # First Need to store ws_id in workspaces table
        self.ws = Workspaces.objects.get()

        super(Consumers, self).save(*args, **kwargs)


class HmacauthCredentials(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    consumer = models.ForeignKey(Consumers, models.DO_NOTHING, blank=True, null=True)
    username = models.TextField(blank=True, null=True)
    secret = models.TextField(blank=True, null=True)
    tags = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    ws = models.ForeignKey('Workspaces', models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'hmacauth_credentials'
        unique_together = (('id', 'ws'), ('ws', 'username'),)

    def save(self, *args, **kwargs):

        # First Need to store ws_id in workspaces table
        self.ws = Workspaces.objects.get()

        super(HmacauthCredentials, self).save(*args, **kwargs)


class JwtSecrets(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    consumer = models.ForeignKey(Consumers, models.DO_NOTHING, blank=True, null=True)
    key = models.TextField(blank=True, null=True)
    secret = models.TextField(blank=True, null=True)
    algorithm = models.TextField(blank=True, null=True)
    rsa_public_key = models.TextField(blank=True, null=True)
    tags = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    ws = models.ForeignKey('Workspaces', models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'jwt_secrets'
        unique_together = (('id', 'ws'), ('ws', 'key'),)

    def save(self, *args, **kwargs):

        # First Need to store ws_id in workspaces table
        self.ws = Workspaces.objects.get()

        super(JwtSecrets, self).save(*args, **kwargs)


class KeyauthCredentials(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    consumer = models.ForeignKey(Consumers, models.DO_NOTHING, blank=True, null=True)
    key = models.TextField(blank=True, null=True)
    tags = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    ttl = models.DateTimeField(blank=True, null=True)
    ws = models.ForeignKey('Workspaces', models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'keyauth_credentials'
        unique_together = (('id', 'ws'), ('ws', 'key'),)

    def save(self, *args, **kwargs):

        # First Need to store ws_id in workspaces table
        self.ws = Workspaces.objects.get()

        super(KeyauthCredentials, self).save(*args, **kwargs)


class Locks(models.Model):
    key = models.TextField(primary_key=True)
    owner = models.TextField(blank=True, null=True)
    ttl = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'locks'


class Oauth2AuthorizationCodes(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    credential = models.ForeignKey('Oauth2Credentials', models.DO_NOTHING, blank=True, null=True)
    service = models.ForeignKey('Services', models.DO_NOTHING, blank=True, null=True)
    code = models.TextField(blank=True, null=True)
    authenticated_userid = models.TextField(blank=True, null=True)
    scope = models.TextField(blank=True, null=True)
    ttl = models.DateTimeField(blank=True, null=True)
    challenge = models.TextField(blank=True, null=True)
    challenge_method = models.TextField(blank=True, null=True)
    ws = models.ForeignKey('Workspaces', models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'oauth2_authorization_codes'
        unique_together = (('id', 'ws'), ('ws', 'code'),)

    def save(self, *args, **kwargs):

        # First Need to store ws_id in workspaces table
        self.ws = Workspaces.objects.get()

        super(Oauth2AuthorizationCodes, self).save(*args, **kwargs)


class Oauth2Credentials(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    name = models.TextField(blank=True, null=True)
    consumer = models.ForeignKey(Consumers, models.DO_NOTHING, blank=True, null=True)
    client_id = models.TextField(blank=True, null=True)
    client_secret = models.TextField(blank=True, null=True)
    redirect_uris = models.TextField(blank=True, null=True)  # This field type is a guess.
    tags = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    client_type = models.TextField(blank=True, null=True)
    hash_secret = models.BooleanField(blank=True, null=True)
    ws = models.ForeignKey('Workspaces', models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'oauth2_credentials'
        unique_together = (('id', 'ws'), ('ws', 'client_id'),)

    def save(self, *args, **kwargs):

        # First Need to store ws_id in workspaces table
        self.ws = Workspaces.objects.get()

        super(Oauth2Credentials, self).save(*args, **kwargs)


class Oauth2Tokens(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    credential = models.ForeignKey(Oauth2Credentials, models.DO_NOTHING, blank=True, null=True)
    service = models.ForeignKey('Services', models.DO_NOTHING, blank=True, null=True)
    access_token = models.TextField(blank=True, null=True)
    refresh_token = models.TextField(blank=True, null=True)
    token_type = models.TextField(blank=True, null=True)
    expires_in = models.IntegerField(blank=True, null=True)
    authenticated_userid = models.TextField(blank=True, null=True)
    scope = models.TextField(blank=True, null=True)
    ttl = models.DateTimeField(blank=True, null=True)
    ws = models.ForeignKey('Workspaces', models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'oauth2_tokens'
        unique_together = (('id', 'ws'), ('ws', 'access_token'), ('ws', 'refresh_token'),)

    def save(self, *args, **kwargs):

        # First Need to store ws_id in workspaces table
        self.ws = Workspaces.objects.get()

        super(Oauth2Tokens, self).save(*args, **kwargs)


class Parameters(models.Model):
    key = models.TextField(primary_key=True)
    value = models.TextField()
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'parameters'


class Plugins(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    name = models.TextField()
    consumer = models.ForeignKey(Consumers, models.DO_NOTHING, blank=True, null=True)
    service = models.ForeignKey('Services', models.DO_NOTHING, blank=True, null=True, related_name='service_plugins')
    route = models.ForeignKey('Routes', models.DO_NOTHING, blank=True, null=True)
    config = models.JSONField()
    enabled = models.BooleanField(default=True)
    cache_key = models.TextField(unique=True, blank=True, null=True)
    protocols = ArrayField(models.TextField(), blank=True, null=True, default=["grpc", "grpcs", "http", "https"]) # This field type is a guess.
    tags = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    ws = models.ForeignKey('Workspaces', models.DO_NOTHING, blank=True, null=True, related_name='plugins')

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'plugins'
        unique_together = (('id', 'ws'),)

    def __str__(self):
        if self.name:
            return str(self.name)
        return str(self.id)


class RatelimitingMetrics(models.Model):
    identifier = models.TextField(primary_key=True)
    period = models.TextField()
    period_date = models.DateTimeField()
    service_id = models.UUIDField()
    route_id = models.UUIDField()
    value = models.IntegerField(blank=True, null=True)
    ttl = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'ratelimiting_metrics'
        unique_together = (('identifier', 'period', 'period_date', 'service_id', 'route_id'),)


class ResponseRatelimitingMetrics(models.Model):
    identifier = models.TextField(primary_key=True)
    period = models.TextField()
    period_date = models.DateTimeField()
    service_id = models.UUIDField()
    route_id = models.UUIDField()
    value = models.IntegerField(blank=True, null=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'response_ratelimiting_metrics'
        unique_together = (('identifier', 'period', 'period_date', 'service_id', 'route_id'),)


class Routes(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    updated_at = models.DateTimeField(blank=True, null=True, auto_now=True)
    name = models.TextField(blank=True, null=True)
    service = models.ForeignKey('Services', models.DO_NOTHING, blank=True, null=True)
    protocols = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    methods = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    hosts = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    paths = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    snis = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    sources = ArrayField(models.JSONField(), blank=True, null=True)  # This field type is a guess.
    destinations = ArrayField(models.JSONField(), blank=True, null=True)  # This field type is a guess.
    regex_priority = models.BigIntegerField(blank=True, null=True, default=0)
    strip_path = models.BooleanField(blank=True, null=True, default=True)
    preserve_host = models.BooleanField(blank=True, null=True, default=True)
    tags = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    https_redirect_status_code = models.IntegerField(blank=True, null=True)
    headers = models.JSONField(blank=True, null=True)
    path_handling = models.TextField(blank=True, null=True, default='v0')
    ws = models.ForeignKey('Workspaces', models.DO_NOTHING, blank=True, null=True, related_name='routes')
    request_buffering = models.BooleanField(blank=True, null=True, default=True)
    response_buffering = models.BooleanField(blank=True, null=True, default=True)
    expression = models.TextField(default='')
    priority = models.BigIntegerField(default=0)
    metadata = models.ForeignKey('KongEntityMetadata', models.DO_NOTHING, blank=True, null=True, related_name='metadata_routes')

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'routes'
        unique_together = (('id', 'ws'), ('ws', 'name'),)

    def __str__(self):
        if self.name:
            return str(self.name)
        return str(self.id)

    def get_upstream(self):
        return Upstreams.objects.get(name=self.name)

    def is_force_https(self):
        return self.protocols == ["https"]

    def tags_to_dict(self):
        tags = {}
        if self.tags:
            for tag in self.tags:
                key, value = tag.replace('"', "").split("=")
                tags[key] = value
        return tags

    @property
    def cname(self):
        tags = self.tags_to_dict()
        return tags.get("cname", '')

    @property
    def domain_cname(self):
        tags = self.tags_to_dict()
        if '*' in self.name:
            self.name = self.name.replace('*', 'all')
        return f"{self.name}.{tags.get('cname', '')}"

    def _gen_for_field(self, name, op, vals, val_transform = None):
        if not vals or vals == None:
            return None

        atc_escape_str = lambda s: "\"" + s + "\""

        values = []

        for p in vals:
            op = (type(op) == str and op or op(p))
            values.append(name + " " + op + " " + atc_escape_str(val_transform and val_transform(op, p) or p))

        if len(values) > 0:
            return "(" + " || ".join(values) + ")"

        return None

    def get_atc(self, route):
        OP_EQUAL    = "=="
        OP_PREFIX   = "^="
        OP_POSTFIX  = "=^"
        OP_REGEX    = "~"
        TILDE = "~"
        ASTERISK = "*"

        def is_regex_magic(path):
            return path[:1] == TILDE

        def paths_resort(paths):
            if not paths:
                return
            sorted(paths, key=functools.cmp_to_key(lambda a, b: is_regex_magic(a) and not is_regex_magic(b)))

        def split_host_port(string):
            if not string.rsplit(':', 1)[-1].isdigit():
                return (string, None)

            string = string.rsplit(':', 1)

            host = string[0]  # 1st index is always host
            port = int(string[1])

            return (host, port)

        out = []

        gen = self._gen_for_field("http.method", OP_EQUAL, route.methods)
        if gen:
            out.append(gen)

        gen = self._gen_for_field("tls.sni", OP_EQUAL, route.snis)
        if gen:
            gen = "net.protocol != \"https\" || " + gen
            out.append(gen)

        if route.hosts and route.hosts != None:
            hosts = []

            for h in route.hosts:
                host, port = split_host_port(h)

                op = OP_EQUAL
                if host[:1] == ASTERISK:
                    op = OP_POSTFIX
                    host = host[2:]
                elif host[-1:] == ASTERISK:
                    op = OP_PREFIX
                    host = host[:-2]

                atc = "http.host " + op + " \"" + host + "\""
                if not port:
                    hosts.append(atc)
                else:
                    hosts.append("(" + atc + " && net.port " + OP_EQUAL + " " + port + ")")

            out.append("(" + " || ".join(hosts) + ")")


        if route.paths != None:
            paths_resort(route.paths)

        def op_callback(path):
            return is_regex_magic(path) and OP_REGEX or OP_PREFIX

        def path_callback(op, p):
            if op == OP_REGEX:
                p = p[1:]
                p = "^" + p
                return p
            return p

        gen = self._gen_for_field("http.path", op_callback, route.paths, path_callback)
        if gen:
            out.append(gen)

        return " && ".join(out)


    def save(self, *args, **kwargs):

        # First Need to store ws_id in workspaces table
        self.ws = Workspaces.objects.get()

        self.expression = self.get_atc(self)

        super(Routes, self).save(*args, **kwargs)


class SchemaMeta(models.Model):
    key = models.TextField(primary_key=True)
    subsystem = models.TextField()
    last_executed = models.TextField(blank=True, null=True)
    executed = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    pending = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'schema_meta'
        unique_together = (('key', 'subsystem'),)


class Services(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    updated_at = models.DateTimeField(blank=True, null=True, auto_now=True)
    name = models.TextField(blank=True, null=True)
    retries = models.BigIntegerField(blank=True, null=True, default=5)
    protocol = models.TextField(blank=True, null=True)
    host = models.TextField(blank=True, null=True)
    port = models.BigIntegerField(blank=True, null=True)
    path = models.TextField(blank=True, null=True)
    connect_timeout = models.BigIntegerField(blank=True, null=True, default=8000)
    write_timeout = models.BigIntegerField(blank=True, null=True, default=8000)
    read_timeout = models.BigIntegerField(blank=True, null=True, default=8000)
    tags = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    client_certificate = models.ForeignKey(Certificates, models.DO_NOTHING, blank=True, null=True)
    tls_verify = models.BooleanField(blank=True, null=True)
    tls_verify_depth = models.SmallIntegerField(blank=True, null=True)
    ca_certificates = ArrayField(models.UUIDField(), blank=True, null=True)  # This field type is a guess.
    ws = models.ForeignKey('Workspaces', models.DO_NOTHING, blank=True, null=True, related_name='services')
    enabled = models.BooleanField(blank=True, null=True, default=True)
    metadata = models.ForeignKey('KongEntityMetadata', models.DO_NOTHING, blank=True, null=True, related_name='metadata_services')

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'services'
        unique_together = (('id', 'ws'), ('ws', 'name'),)

    def __str__(self):
        if self.name:
            return str(self.name)
        return str(self.id)

    def tags_to_dict(self):
        tags = {}
        for tag in self.tags:
            key, value = tag.replace('"', "").split("=")
            tags[key] = value
        return tags

    @property
    def cname(self):
        tags = self.tags_to_dict()
        return tags["cname"]

    def save(self, *args, **kwargs):

        # First Need to store ws_id in workspaces table
        self.ws = Workspaces.objects.get()

        if self.port == 80:
            self.protocol = 'http'
        else:
            self.protocol = 'https'

        super(Services, self).save(*args, **kwargs)


class Sessions(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session_id = models.TextField(unique=True, blank=True, null=True)
    expires = models.IntegerField(blank=True, null=True)
    data = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    ttl = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'sessions'


class Snis(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    name = models.TextField(unique=True)
    certificate = models.ForeignKey(Certificates, models.DO_NOTHING, blank=True, null=True)
    tags = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    ws = models.ForeignKey('Workspaces', models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'snis'
        unique_together = (('id', 'ws'),)

    def __str__(self):
        return str(self.id)

    def save(self, *args, **kwargs):

        # First Need to store ws_id in workspaces table
        self.ws = Workspaces.objects.get()

        super(Snis, self).save(*args, **kwargs)


class Tags(models.Model):
    entity_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    entity_name = models.TextField(blank=True, null=True)
    tags = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'tags'


class Targets(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=True)
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    upstream = models.ForeignKey('Upstreams', models.DO_NOTHING, blank=True, null=True)
    target = models.TextField()
    weight = models.IntegerField(default=100)
    tags = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    ws = models.ForeignKey('Workspaces', models.DO_NOTHING, blank=True, null=True, related_name='targets')

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'targets'
        unique_together = (('id', 'ws'),)

    def __str__(self):
        return str(self.id)

    def save(self, *args, **kwargs):

        # First Need to store ws_id in workspaces table
        self.ws = Workspaces.objects.get()

        # Default port 80
        target_split = self.target.split(':')
        if len(target_split) == 1:
            self.target += ':80'

        super(Targets, self).save(*args, **kwargs)


class Ttls(models.Model):
    primary_key_value = models.TextField(primary_key=True)
    primary_uuid_value = models.UUIDField(blank=True, null=True)
    table_name = models.TextField()
    primary_key_name = models.TextField()
    expire_at = models.DateTimeField()

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'ttls'
        unique_together = (('primary_key_value', 'table_name'),)


class Upstreams(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    name = models.TextField(blank=True, null=True)
    hash_on = models.TextField(blank=True, null=True, default=None)
    hash_fallback = models.TextField(blank=True, null=True, default=None)
    hash_on_header = models.TextField(blank=True, null=True)
    hash_fallback_header = models.TextField(blank=True, null=True)
    hash_on_cookie = models.TextField(blank=True, null=True)
    hash_on_cookie_path = models.TextField(blank=True, null=True, default='/')
    slots = models.IntegerField(default=10000)
    healthchecks = models.JSONField(blank=True, null=True)
    tags = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.
    algorithm = models.TextField(blank=True, null=True)
    host_header = models.TextField(blank=True, null=True)
    client_certificate = models.ForeignKey(Certificates, models.DO_NOTHING, blank=True, null=True)
    ws = models.ForeignKey('Workspaces', models.DO_NOTHING, blank=True, null=True, related_name='upstreams')

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'upstreams'
        unique_together = (('id', 'ws'), ('ws', 'name'),)

    def __str__(self):
        if self.name:
            return str(self.name)
        return str(self.id)

    def save(self, *args, **kwargs):

        # First Need to store ws_id in workspaces table
        self.ws = Workspaces.objects.get()
        self.hash_fallback = 'none'
        self.hash_on = 'none'
        super(Upstreams, self).save(*args, **kwargs)


class VaultsBeta(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=True)
    ws = models.ForeignKey('Workspaces', models.DO_NOTHING, blank=True, null=True)
    prefix = models.TextField(unique=True, blank=True, null=True)
    name = models.TextField()
    description = models.TextField(blank=True, null=True)
    config = models.JSONField()
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)
    tags = ArrayField(models.TextField(), blank=True, null=True)  # This field type is a guess.

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'vaults_beta'
        unique_together = (('id', 'ws'), ('prefix', 'ws'),)


class Workspaces(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=True)
    name = models.TextField(unique=True, blank=True, null=True)
    comment = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    meta = models.JSONField(blank=True, null=True)
    config = models.JSONField(blank=True, null=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'workspaces'

    def __str__(self):
        return str(self.id)


class KongEntityMetadata(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=True)
    description = models.TextField(blank=True, null=True)
    config = models.JSONField(blank=True, null=True)
    entity_id = models.UUIDField(default=uuid.uuid4)
    entity_type = models.IntegerField(
        default=KONG_ROUTE,
        choices=KONG_CHOICES
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        managed = False
        app_label = "kong"
        db_table = 'metadatas'

    def __str__(self):
        return str(self.id)

    @classmethod
    def get_entity_type_description(cls, entity_type, entity_id):
        try:
            obj = cls.objects.filter(entity_type=entity_type, entity_id=entity_id).first()
            return obj.description if obj and obj.description else ""
        except Exception as error:
            print("Metadata get_entity_type_description ERROR:", error)
            return ""

    @classmethod
    def get_entity_type_has_cert(cls, entity_type, entity_id):
        try:
            obj = cls.objects.filter(entity_type=entity_type, entity_id=entity_id).first()
            return obj.config["has_cert"] if obj and obj.config and "has_cert" in obj.config else False
        except Exception as error:
            print("Metadata get_entity_type_description ERROR:", error)
            return ""

    @classmethod
    def create_or_update(cls, entity_type, data):
        try:
            entity_id = data["entity_id"] if "entity_id" in data else ""
            description = data["description"] if "description" in data else ""
            has_cert = data["has_cert"] if "has_cert" in data else False

            if entity_id:
                obj = cls.objects.filter(entity_type=entity_type, entity_id=entity_id).first()
                if not obj:
                    obj = cls.objects.create(
                        entity_id=entity_id,
                        entity_type=entity_type,
                        description=description,
                        config={"has_cert": has_cert}
                    )
                    if entity_type == KONG_ROUTE:
                        route = Routes.objects.get(id=entity_id)
                        route.metadata_id = obj.id
                        route.save()
                    elif entity_type == KONG_SERVICE:
                        service = Services.objects.get(id=entity_id)
                        service.metadata_id = obj.id
                        service.save()
                else:
                    if description:
                        obj.description = description
                    if "has_cert" in data:
                        obj.config["has_cert"] = data["has_cert"]

                    obj.save()
        except Exception as error:
            print("Metadata create_or_update ERROR:", error)
            return None

    @classmethod
    def delete_metadata(cls, entity_type, entity_id):
        try:
            metadata = cls.objects.filter(entity_type=entity_type, entity_id=entity_id).first()
            if metadata:
                metadata_id = metadata.id
                metadata.delete()
                if entity_type == KONG_ROUTE:
                    route = Routes.objects.filter(metadata=metadata_id).first()
                    if route:
                        route.metadata_id = ""
                        route.save()
                elif entity_type == KONG_SERVICE:
                    service = Services.objects.filter(metadata=metadata_id).first()
                    if service:
                        service.metadata_id = ""
                        service.save()
        except Exception as error:
            print("KongEntityMetadata delete_metadata ERROR:", error)
            return None

    @classmethod
    def search_metadata(cls, entity_ids, entity_type, q):
        try:
            return cls.objects.filter(entity_id__in=entity_ids, entity_type=entity_type, description__icontains=q).all()
        except Exception as error:
            print("KongEntityMetadata search_metadata ERROR:", error)
            return None

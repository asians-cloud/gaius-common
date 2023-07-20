/**
 * This pipeline will build and deploy a Docker image with Kaniko
 * https://github.com/GoogleContainerTools/kaniko
 * without needing a Docker host
 *
 * You need to create a jenkins-docker-cfg secret with your docker config
 * as described in
 * https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/#create-a-secret-in-the-cluster-that-holds-your-authorization-token
 *
 * ie.
 * kubectl create secret docker-registry regcred --docker-server=https://index.docker.io/v1/ --docker-username=csanchez --docker-password=mypassword --docker-email=john@doe.com
 */

def project = 'gaius'
def appName = 'common'
def servicename = "${project}-${appName}"
def registry = "asians.azurecr.io"
def imageTag = "${registry}/${project}/${appName}:${env.BUILD_NUMBER}"
def helmChart = "django/django-django"
def testPrompt = false
def Dockerfile = "compose/production/django/Dockerfile"
def cause = currentBuild.getBuildCauses('hudson.model.Cause$UserIdCause')

pipeline {
  agent {
    kubernetes {
      inheritFrom 'kaniko'
    }
  }

  environment {
      registryCredential = 'acr-credentials'
  }

  stages {
    stage('Install Dependencies') {
      steps {
        container(name: 'helm') {
          sh 'helm version'
          sh "helm repo add django https://asians-cloud.github.io/django-helm/charts/"
          sh "helm repo update"
        }
      }
    }

    stage('Build Environment') {
      steps {
        container(name: 'jinja2') {
          dir("chart") {
            sh 'jinja2 --format=json env.yaml.j2 /.gaius-env.json -o env.yaml'
          }
        }
      }
    }

    stage('Build with Kaniko') {
      environment {
        PATH = "/busybox:/kaniko:$PATH"
      }
      steps {
        container(name: 'kaniko', shell: '/busybox/sh') {
          sh """#!/busybox/sh
          /kaniko/executor -f `pwd`/${Dockerfile} -c `pwd` --skip-tls-verify --cache=true --destination=${imageTag}
          """
        }
      }
    }

    stage('Deploy to Prod') {
      steps {
        container(name: 'helm', shell: '/bin/sh') {
          sh 'helm version'

          withKubeConfig([credentialsId: 'k8s-gaius']) {
            dir("chart") {
              sh "helm upgrade --install ${servicename} $helmChart -f ./env.yaml --set image.tag=${env.BUILD_NUMBER} --wait"
            }
          }
        }
      }
    }

    stage('Prod Confirm') {
      steps {
        script {
          try {
            timeout(time: 1, unit: 'HOURS') { // change to a convenient timeout for you
              testPrompt = input(
                  id: 'UAT tested', message: 'Has it Tested?', parameters: [
                  [$class: 'BooleanParameterDefinition', defaultValue: false, description: '', name: 'Please confirm all things are working']
                  ])
            }
          } catch(err) { // input false
              def user = err.getCauses()[0].getUser()
              userInput = false
              echo "Aborted by: [${user}]"
          }
        }
      }
    }
  }

  // Post-build actions
  post {
    always {
      script {
        jobLink = "https://jenkins.asians.cloud/job/${JOB_NAME}/${BUILD_NUMBER}/"
      }
      echo 'Notification Trigger point.'
      discordSend description: "Project Pipeline for ${project} ${appName} \n Job Name : ${currentBuild.projectName} \n Job Status : ${currentBuild.currentResult} \n Triggered by: ${cause.userName}", footer: "", link: "${jobLink}", image: '', result: currentBuild.currentResult, scmWebUrl: '', thumbnail: '', title: "Gaius - ${appName}", webhookURL: "${webHook}"
    }
  }
}

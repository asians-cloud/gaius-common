def helmChart = "django/django-django"
def testPrompt = false
def Dockerfile = "compose/production/django/Dockerfile"
def cause = currentBuild.getBuildCauses('hudson.model.Cause$UserIdCause')

def createDeployment (deployStageName, helmChart) {
  return stage(deployStageName) {
    container(name: 'helm', shell: '/bin/sh') {
      sh 'helm version'

      withKubeConfig([credentialsId: 'k8s-gaius']) {
        dir("chart") {
          sh "helm upgrade --install ${serviceName} $helmChart -f ./env.yaml --set image.tag=${env.BUILD_NUMBER} --wait"
        }
      }
    }
  }
}

def createConfirmation (confirmStageName, cause) {
  return stage(confirmStageName) {
    script {
      try {
        timeout(time: 1, unit: 'HOURS') { // change to a convenient timeout for you
          testPrompt = input(
              id: "${environment} tested", message: 'Has the new change been tested?', parameters: [
              [$class: 'BooleanParameterDefinition', defaultValue: false, description: '', name: 'Please confirm that all functionalities are working.']
              ])
        }
      } catch(err) { // input false
          def user = cause.userName
          userInput = false
          echo "Aborted by: [${user}]"
      }
    }
  }
}

pipeline {
  agent {
    kubernetes {
      inheritFrom 'kaniko'
    }
  }

  environment {
    environment = credentials('environment')
    acrUrl = credentials("acr-url")
    project = "gaius-${environment}"
    appName = 'common'
    serviceName = "${project}-${appName}"
    imageTag = "${acrUrl}/${project}/${appName}:${env.BUILD_NUMBER}"
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
            sh "jinja2 --format=json env.yaml.j2 /.$project-env.json -o env.yaml"
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
          /kaniko/executor -f `pwd`/${Dockerfile} -c `pwd` --skip-tls-verify --cache=true --destination=${imageName}
          """
        }
      }
    }

    stage ('Prepare for release') {
      steps {
        script {
          def capitalizedEnvironment = environment.toUpperCase()
          createDeployment('Deploy to ' + capitalizedEnvironment, helmChart, helmCeleryChart)
          createConfirmation(capitalizedEnvironment + ' Confirmation', cause)
        }
      }
    }
  }

  // Post-build actions
  post {
    always {
      script {
        jobLink = "${env.BUILD_URL}"
      }
      echo 'Notification Trigger point.'
      discordSend description: "Project Pipeline for ${project} ${appName} \n Job Name : ${currentBuild.projectName} \n Job Status : ${currentBuild.currentResult}", footer: "", link: "${jobLink}", image: "${imageTag}", result: currentBuild.currentResult, scmWebUrl: '', thumbnail: '', title: "Gaius - ${appName}", webhookURL: "${webHook}"
    }
  }
}

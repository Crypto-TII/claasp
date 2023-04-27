pipeline {
    environment {
        SLACK_CHANNEL = "#tii-cryptalib-ci-notifications"
        BUILT_IMAGE = "repo.crypto.tii.ae/docker/claasp/sage:latest"
    }
    agent { label 'base-agent' }
    stages {
        stage('Build docker image') {
            steps {
                script {
                    imageInfo = dockerImage.build("claasp/sage", "docker/Dockerfile")
                    BUILT_IMAGE = imageInfo.name
                }
            }
        }
        stage('Build and Test') {
            agent {
                 kubernetes {
                    defaultContainer 'sage'
                    yaml """
                        spec:
                            containers:
                            - name: sage
                              image: ${BUILT_IMAGE}
                              command:
                              - sleep
                              args:
                              - 99d
                        """
                }
            }
            stages {
                stage("Run pytest with coverage"){
                    steps {
                        script {
                            sh """
                                make jenkins-pytest
                            """
                        }
                    }
                }
                stage('SonarQube analysis') {
                    steps {
                        script {
                            sonar.scanProject()
                        }
                    }
                }
            }
        }
    }
    post {
        always {
            script {
                notify currentBuild.result
            }
        }
    }
}
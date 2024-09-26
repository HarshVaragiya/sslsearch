pipeline {
    agent any
    stages {
        stage("build"){
            steps {
                sh "docker build -t ${REPOSITORY}/sslsearch:${IMAGE_TAG} ."
            }
        }
        stage("push") {
            steps{
                sh "docker push ${REPOSITORY}/sslsearch:${IMAGE_TAG}"
            }
        }
    }
}
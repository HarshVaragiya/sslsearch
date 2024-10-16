pipeline {
    agent any
    stages {
        stage("build"){
            steps {
                sh "docker buildx build --platform linux/arm64,linux/amd64 --tag ${REPOSITORY}/sslsearch:${IMAGE_TAG} ."
            }
        }
        stage("push") {
            steps{
                sh "docker push ${REPOSITORY}/sslsearch:${IMAGE_TAG}"
            }
        }
    }
}

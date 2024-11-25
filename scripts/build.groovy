pipeline {
    agent any
    stages {
        stage("build"){
            steps {
                sh "docker buildx build --push --platform linux/arm64,linux/amd64 --tag ${REPOSITORY}/sslsearch:${IMAGE_TAG} ."
            }
        }
    }
}

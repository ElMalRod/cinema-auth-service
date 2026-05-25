pipeline {
    agent any

    environment {
        SERVICE_NAME  = 'cinema-auth-service'
        SERVICE_PORT  = '8081'
        KAFKA_SERVERS = '18.188.55.33:9092'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Tests') {
            steps {
                sh 'mvn test'
            }
            post {
                always {
                    junit '**/target/surefire-reports/*.xml'
                }
            }
        }

        stage('Code Coverage') {
            steps {
                sh 'mvn verify'
                script {
                    echo 'JaCoCo coverage checks passed (LINE >= 85% and BRANCH >= 85%).'
                }
            }
        }

        stage('Build JAR') {
            steps {
                sh 'mvn clean package -DskipTests'
            }
        }

        stage('Build Docker Image') {
            steps {
                sh "docker build -t ${SERVICE_NAME}:latest ."
            }
        }

        stage('Transfer Image') {
            steps {
                withCredentials([
                    string(credentialsId: 'EC2_SERVICES_HOST', variable: 'HOST')
                ]) {
                    sshagent(['SSH_DEPLOY_KEY']) {
                        sh '''
                            rm -f cinema-auth-service.tar.gz || true

                            docker save cinema-auth-service:latest | gzip > cinema-auth-service.tar.gz

                            scp -o StrictHostKeyChecking=no \
                                cinema-auth-service.tar.gz \
                                ubuntu@"$HOST":~/
                        '''
                    }
                }
            }
        }

        stage('Deploy') {
            steps {
                withCredentials([
                    string(credentialsId: 'EC2_SERVICES_HOST', variable: 'HOST'),
                    string(credentialsId: 'DB_URL_AUTH', variable: 'DB_URL'),
                    string(credentialsId: 'DB_USERNAME', variable: 'DB_USER'),
                    string(credentialsId: 'DB_PASSWORD', variable: 'DB_PASS'),
                    string(credentialsId: 'BREVO_API_KEY', variable: 'BREVO_KEY'),
                    string(credentialsId: 'BREVO_SENDER_EMAIL', variable: 'BREVO_EMAIL')
                ]) {
                    sshagent(['SSH_DEPLOY_KEY']) {
                        sh '''
                            ssh -o StrictHostKeyChecking=no ubuntu@"$HOST" "
                                set -e

                                docker load < ~/cinema-auth-service.tar.gz

                                rm -f ~/cinema-auth-service.tar.gz

                                docker stop cinema-auth-service || true
                                docker rm cinema-auth-service || true

                                docker run -d \
                                    --name cinema-auth-service \
                                    --restart unless-stopped \
                                    --network cinema-network \
                                    -p 8081:8081 \
                                    -e SERVER_PORT=8081 \
                                    -e DB_URL='$DB_URL' \
                                    -e DB_USERNAME='$DB_USER' \
                                    -e DB_PASSWORD='$DB_PASS' \
                                    -e BREVO_API_KEY='$BREVO_KEY' \
                                    -e BREVO_SENDER_EMAIL='$BREVO_EMAIL' \
                                    -e SPRING_FLYWAY_BASELINE_ON_MIGRATE=true \
                                    -e SPRING_FLYWAY_BASELINE_VERSION=0 \
                                    -e SPRING_KAFKA_BOOTSTRAP_SERVERS='18.188.55.33:9092' \
                                    cinema-auth-service:latest
                            "
                        '''
                    }
                }
            }
        }

        stage('Health Check') {
            steps {
                withCredentials([
                    string(credentialsId: 'EC2_SERVICES_HOST', variable: 'HOST')
                ]) {
                    sshagent(['SSH_DEPLOY_KEY']) {
                        sh '''
                            ssh -o StrictHostKeyChecking=no ubuntu@"$HOST" "
                                sleep 20

                                docker ps | grep cinema-auth-service

                                docker logs --tail 50 cinema-auth-service
                            "
                        '''
                    }
                }
            }
        }
    }

    post {
        success {
            echo 'cinema-auth-service deployed successfully'
        }

        failure {
            echo 'Pipeline failed for cinema-auth-service'
        }

        always {
            sh 'rm -f cinema-auth-service.tar.gz || true'
        }
    }
}

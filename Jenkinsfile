pipeline {
    agent any

    environment {
        SERVICE_NAME      = 'cinema-auth-service'
        SERVICE_PORT      = '8081'
        KAFKA_SERVERS     = '18.188.55.33:9092'
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
                    def coverage = sh(
                        script: '''
                            awk -F"," '
                            NR>1 {
                                missed += $4; covered += $5
                            }
                            END {
                                if (missed+covered > 0)
                                    printf "%.0f", covered*100/(missed+covered)
                                else
                                    print "0"
                            }' target/site/jacoco/jacoco.csv
                        ''',
                        returnStdout: true
                    ).trim()
                    echo "Code coverage: ${coverage}%"
                    if (coverage.toInteger() < 85) {
                        error "Coverage ${coverage}% es menor al 85% requerido"
                    }
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
                sh "docker build -t ${env.SERVICE_NAME}:latest ."
            }
        }

        stage('Transfer Image') {
            steps {
                withCredentials([
                    string(credentialsId: 'EC2_SERVICES_HOST', variable: 'HOST')
                ]) {
                    sshagent(['SSH_DEPLOY_KEY']) {
                        sh '''
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
                    string(credentialsId: 'EC2_SERVICES_HOST',  variable: 'HOST'),
                    string(credentialsId: 'DB_URL_AUTH',         variable: 'DB_URL'),
                    string(credentialsId: 'DB_USERNAME',         variable: 'DB_USER'),
                    string(credentialsId: 'DB_PASSWORD',         variable: 'DB_PASS'),
                    string(credentialsId: 'BREVO_API_KEY',       variable: 'BREVO_KEY'),
                    string(credentialsId: 'BREVO_SENDER_EMAIL',  variable: 'BREVO_EMAIL')
                ]) {
                    sshagent(['SSH_DEPLOY_KEY']) {
                        sh '''
                            ssh -o StrictHostKeyChecking=no ubuntu@"$HOST" "
                                docker load < cinema-auth-service.tar.gz
                                docker stop cinema-auth-service || true
                                docker rm   cinema-auth-service || true
                                docker run -d \\
                                    --name cinema-auth-service \\
                                    --restart unless-stopped \\
                                    --network cinema-network \\
                                    -e DB_URL='$DB_URL' \\
                                    -e DB_USERNAME='$DB_USER' \\
                                    -e DB_PASSWORD='$DB_PASS' \\
                                    -e BREVO_API_KEY='$BREVO_KEY' \\
                                    -e BREVO_SENDER_EMAIL='$BREVO_EMAIL' \\
                                    -e SPRING_FLYWAY_BASELINE_ON_MIGRATE=true \\
                                    -e SPRING_FLYWAY_BASELINE_VERSION=0 \\
                                    -e SPRING_KAFKA_BOOTSTRAP_SERVERS=18.188.55.33:9092 \\
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
                                docker exec cinema-auth-service curl -f http://localhost:8081/actuator/health
                            "
                        '''
                    }
                }
            }
        }
    }

    post {
        success {
            echo "cinema-auth-service desplegado correctamente"
        }
        failure {
            echo "Pipeline falló en cinema-auth-service"
        }
        always {
            sh 'rm -f cinema-auth-service.tar.gz || true'
        }
    }
}
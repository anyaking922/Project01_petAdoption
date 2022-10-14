pipeline{
    agent any
    tools {
        maven 'maven'
    }
    stages {
        stage('Pull Source Code from Github'){
            steps{
               git branch: 'main',
               credentialsId: 'd07bde12-3e29-4f90-985a-411a14a30a5e',
               url: 'https://github.com/anyaking922/ApplicationBuilder.git'
               
            }
        }
        stage('Code Analysis'){
            steps{
                withSonarQubeEnv('sonarQube') {
                    sh "mvn sonar:sonar"
                }
            }
        }
        stage('Building Source Code') {
            steps{
               sh 'mvn package -Dmaven.test.skip'
            }
        }
        stage('Sending Artifacts') {
            steps{
                sshagent(['jenkinskey']) {
                sh 'scp -o StrictHostKeyChecking=no /var/lib/jenkins/workspace/pet-adoption/target/spring-petclinic-2.4.2.war ec2-user@52.51.97.177:/opt/docker'
                }
             }
        }
    }
}

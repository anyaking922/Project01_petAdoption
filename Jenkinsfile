pipeline{
    agent any
    tools {
        maven 'maven'
    }
    stages {
        stage('Pull Source Code from Github'){
            steps{
               git branch: 'main',
               credentialsId: 'GitCred',
               url: 'https://github.com/anyaking922/Project01_petAdoption.git'
               
            }
        }
        stage('Code Analysis'){
            steps{
                withSonarQubeEnv('sonar') {
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
                sh 'scp -o StrictHostKeyChecking=no /var/lib/jenkins/workspace/pet-adoption/target/spring-petclinic-2.4.2.war ec2-user@52.50.14.179:/opt/docker'
                }
             }
        }
    }
}

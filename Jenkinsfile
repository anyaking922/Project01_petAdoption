pipeline {
  agent any
  tools {
  maven 'maven'
}
  stages {
      stage('Pull Source Code from GitHub') {
          steps {
              git branch: 'main',
              credentialsId: '	f641d140-c071-4b64-9334-5c616f8c47fa',
              url: 'https://github.com/anyaking922/Project01_petAdoption.git'
          }      
    }
    stage('Code Analysis') {
      steps {
        withSonarQubeEnv('sonar') {
          sh "mvn compile sonar:sonar"
        }
      }
    }
    stage('Build Code') {
      steps {
        sh 'mvn package -Dmaven.test.skip'
      }
    }

    stage('Send Artifacts') {
      steps {
        sshagent(['ansible-prv-key']) {
          sh 'scp -o StrictHostKeyChecking=no /var/lib/jenkins/workspace/pac-project/target/spring-petclinic-2.4.2.war ec2-user@54.229.122.183:/home/ubuntu/Docker'
        }
      }
    }
    stage('Deploy Application') {
      steps {
        sshagent(['ansible-prv-key']) {
          sh 'ssh -o strictHostKeyChecking=no ec2-user@54.229.122.183 "cd /home/ubuntu/Ansible && ansible-playbook playbook-dockerimage.yaml && ansible-playbook playbook-container.yaml && ansible-playbook playbook-newrelic.yaml"'
        }
      }
    }
  }
}


output "JenkinsIP" {
  value = aws_instance.PACD_Jenkins_Host.public_ip
}

output "DockerIP" {
  value = aws_instance.PACD_Docker_Host.public_ip
}


output "AnsibleIP" {
  value = aws_instance.PACD_Ansible_Host.public_ip
}

output "SonarIP" {
  value = aws_instance.Sonarqube_Server.public_ip
}








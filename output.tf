
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

# output "alb_dns" {
#   value = aws_lb.PACD_lb.dns_name
# }

# output "name_servers" {
#   value = aws_route53_zone.PACD_hosted_zone.name_servers
# }





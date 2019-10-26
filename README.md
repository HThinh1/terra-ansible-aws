apt update

# Teraform install 
curl -O https://releases.hashicorp.com/terraform/0.11.2/terraform_0.11.2_linux_amd64.zip
mkdir /bin/terraform
unzip terraform_0.11.2_linux_amd64.zip -d /bin/terraform
export PATH=$PATH:/bin/terraform


# Install AWSCLI
apt install python-pip
pip install awscli --upgrade

# Install Ansible
apt install software-properties-common
apt-add-repository ppa:ansible/ansible
apt update
apt install ansible
vim /etc/ansible/ansible.cfg (uncomment `#host_key_checking = False`)

# Final setup
ssh-keygen (insert path: ~/.ssh/<name> )
## Do every time login again
ssh-agent bash
ssh-add ~/.ssh/<name>
ssh-add -l

# Create the following file
touch aws_hosts  main.tf  s3update.yml  terraform.tfvars  userdata  variables.tf  wordpress.yml

#  To beautify code
terraform fmt <--diff: show which file is corrected>

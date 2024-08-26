#Ensure SSH Access is limited 
control "cisecurity.benchmarks_rule_5.2.15_Ensure_SSH_access_ is_limited" do
   title "Ensure SSH access is limited"
   desc "There are several options available to limit which users and group can access the system via SSH. It is recommended that at least one of the following options be leveraged: AllowUsers, AllowGroups, DenyUsers, or DenyGroups. Rationale: Restricting which users
   can remotely access the system via SSH will help ensure that only authorized users access the system." 
   impact 1.0
   tag "cis-rhel7-2.1.1": "5.2.15"
   tag "level": "1"
   tag "type": ["Server", "Workstation"] 
   describe.one do
     describe sshd_config do
       its('AllowUsers') { should match /[\S|\s]+/ } 
     end
     describe sshd_config do
       its('AllowGroups') { should match /[\S|\s]+/ } 
     end
     describe sshd_config do
       its('DenyUsers') { should match /[\S|\s]+/ } 
     end
     describe sshd_config do
       its('DenyGroups') { should match /[\S|\s]+/ } 
     end
    end 
end
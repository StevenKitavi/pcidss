control "cisecurity.benchmarks_rule_6.2.1_Ensure_password_fields_are_ not_empty" do
 title "Ensure password fields are not empty"
    desc "An account with an empty password field means that anybody may log in as that user without providing a password. Rationale: All accounts must have passwords or be locked to prevent the account from being used by an unauthorized user."
    impact 1.0
 tag "cis-ubuntu-24.04": "6.2.1"
 tag "level": "1"
  tag "type": ["Server", "Workstation"] 
  shadow.users(/.+/).entries.each do |entry|
    describe entry do
       its('passwords') { should_not eq [''] } 
      end
   end 
end
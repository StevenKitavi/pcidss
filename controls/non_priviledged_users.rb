control "mycompany.custom_rule1.0.0_Ensure_non_privileged_users_cant_ access_cc_numbers" do
  title "Ensure that non-privileged database users do not see CC numbers"
  desc "A legitimate and authorized database user account should not be able to access credit card numbers if they are not specifically authorized to do so. Rationale: Only privileged accounts should be able to access cardholder data."
  impact 1.0
  tag "level": "1"
  tag "type": ["Server", "Workstation"]
  %w[sys system alice].each do |unprivileged|
    describe oracledb_session(user: unprivileged, password:'password', service:'ora01.mycompany.com').query('SELECT creditcard FROM accounts'). rows do
  its('count') { should eq 0 } 
      end
   end
end
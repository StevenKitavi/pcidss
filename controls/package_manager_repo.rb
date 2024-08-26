control "cisecurity.benchmarks_rule_1.2.1_Ensure_pkg_manager_repos_are_configured" do
  title "Ensure package manager repositories are configured"
  
  desc "Systems need to have package manager repositories configured to ensure they receive the latest patches and updates. 
  Rationale: If a system's package repositories are misconfigured, important patches may not be identified or a rogue repository could introduce compromised software."

  impact 0.0
  tag "cis-ubuntu20.04": "1.2.0"
  tag "level": "1"
  tag "type": ["Server", "Workstation"]

  REDHAT_REPOS.each do |repository|
    describe yum.repo(repository) do
      it { should exist }
      it { should be_enabled }
    end
  end

  cmd = command('yum repolist enabled').stdout.split("\n")
  get_other_repos = cmd.slice(2..cmd.length - 2) || []
  other_repos = get_other_repos.map { |repositories| repositories.gsub(/\s.+/, '') }
  other_repos -= REDHAT_REPOS

  unless other_repos.empty?
    other_repos.each do |repository|
      describe yum.repo(repository) do
        it { should_not exist }
        it { should_not be_enabled }
      end
    end
  end
end

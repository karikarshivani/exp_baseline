# encoding: UTF-8

control "1.1" do
  title "Ensure Latest SQL Server Cumulative and Security Updates are 
Installed (Manual)"
  desc "Text"
  desc "rationale", "Text"
  desc "check", "Text"
  desc "fix", "Text"
  desc "default_value", "Cumulative and security updates are not installed by default."
  impact 0.5
  tag nist: []
  tag severity: "medium"
  tag cis_controls: "Controls"

  sql_session = mssql_session(
    user: input('user'),
    password: input('password'),
    host: input('host'),
    instance: input('instance'),
    port: input('port'))

  query = %{
    SELECT SERVERPROPERTY('ProductLevel') as SP_installed,
    SERVERPROPERTY('ProductVersion') as Version;
    GO
    }

  describe "Baseline: SQL Version" do
    subject { sql_session.query(query).column('version').uniq }
    it { should match_array input('sql_version') }
  end
end
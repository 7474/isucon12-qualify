directory '/home/isucon-admin/blackauth' do
  owner 'isucon-admin'
  group 'isucon-admin'
  mode '0755'
end

remote_file '/home/isucon-admin/blackauth/blackauth' do
  owner 'isucon-admin'
  group 'isucon-admin'
  mode '0755'
  source 'blackauth'
end

remote_file '/etc/systemd/system/blackauth.service' do
  owner 'root'
  group 'root'
  mode '0644'
  source 'blackauth.service'
end

execute 'systemctl enable blackauth' do
  command 'systemctl daemon-reload && systemctl enable blackauth'
  only_if { !File.exist?("/.dockerenv") }
end

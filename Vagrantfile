# Metasploitable 3 (Linux, Ubuntu 14.04, kernel ~3.13) — the TARGET VM.
# It is a VM on purpose: the privesc kernel exploits (overlayfs CVE-2015-1328,
# DirtyCow) need a real guest kernel, which a container cannot provide.
#
#   vagrant up            # boots the target
#   vagrant ssh target    # (creds vagrant/vagrant)
#   vagrant halt          # stop        vagrant destroy   # remove
#
# TARGET_IP env var (or the default below) sets the host-only network IP the
# attacker will scan. Point your Kali container/host at the same subnet — see
# REPRODUCIBILITY.md "Networking".
#
# BOX AVAILABILITY: the box name below is the Rapid7-published MS3 Ubuntu 1404
# image. If `vagrant up` can't fetch it, build it locally from
# https://github.com/rapid7/metasploitable3 (Packer): `./build.sh ub1404`, then
# `vagrant box add` the resulting .box and set `t.vm.box` to that name.

Vagrant.configure("2") do |config|
  config.vm.define "target" do |t|
    t.vm.box = "rapid7/metasploitable3-ub1404"
    t.vm.hostname = "metasploitable3-ub1404"

    # Host-only network. Keep this on the SAME subnet your attacker uses.
    t.vm.network "private_network", ip: ENV.fetch("TARGET_IP", "192.168.34.7")

    t.vm.provider "virtualbox" do |vb|
      vb.name = "lgg-metasploitable3"
      vb.memory = 2048
      vb.cpus = 2
      # MS3 runs many services; give it headroom.
    end
  end
end

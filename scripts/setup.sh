sudo apt-get -y install python3 python3-gi gir1.2-gtk-3.0 gir1.2-webkit2-4.0
pip3 install requests
cd ../..
sudo rm -rf /opt/gp-saml-gui
sudo mkdir /opt/gp-saml-gui
sudo cp -r gp-saml-gui/* /opt/gp-saml-gui
echo $REPLY > gp-saml-gui/scripts/gp.conf
sudo rm -f /usr/local/bin/mvpn
sudo rm -f /usr/local/bin/dvpn
sudo ln -s  /opt/gp-saml-gui/scripts/vpn.sh /usr/local/bin/mvpn
sudo ln -s  /opt/gp-saml-gui/scripts/disconnectVPN.sh /usr/local/bin/dvpn
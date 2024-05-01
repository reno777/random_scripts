#!/bin/bash

#This sets up Zsh on debian based devices

sudo apt update && sudo apt upgrade -y && sudo apt autoremove && sudo apt install zsh -y
sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"
git clone https://github.com/powerline/fonts.git
cd fonts/
./install.sh
git clone https://github.com/romkatv/powerlevel10k.git ~/.oh-my-zsh/custom/themes/powerlevel10k
cd ~
sed -i 's@ZSH_THEME="robbyrussel"@ZSH_THEME="powerlevel10k/powerlevel10k"@g' .zshrc
echo 'alias zshconfig="vim ~/.zshrc"' >> .zshrc
echo 'alias ipinfo="curl ipinfo.io"' >> .zshrc
echo 'POWERLEVEL9K_LEFT_PROMPT_ELEMENTS=(context dir vcs)' >> .zshrc
echo 'POWERLEVEL9K_RIGHT_PROMPT_ELEMENTS=(status public_ip vpn_ip date time_joined)' >> .zshrc
echo "POWERLEVEL9K_CONTEXT_DEFAULT_FOREGROUND='green'" >> .zshrc
sed -i 's/plugins=(git)/plugins=(git encode64 extract python pep8)/g' .zshrc

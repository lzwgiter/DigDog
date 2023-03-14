#!/bin/bash

# 切换pip源
function change_pip_source {
	echo -e "\033[33m=== pip已切换为国内源 https://pypi.tuna.tsinghua.edu.cn/simple ===\033[0m"
	if [ ! -d ~/.pip ]
	then
        mkdir ~/.pip
        touch ~/.pip/pip.conf
        echo "[global]" > ~/.pip/pip.conf
        echo "index-url = https://pypi.tuna.tsinghua.edu.cn/simple" >> ~/.pip/pip.conf
        echo "trusted-host = https://pypi.tuna.tsinghua.edu.cn/simple" >> ~/.pip/pip.conf
    fi

    if [ ! -f ~/.pip/pip.conf ]
    then
        touch ~/.pip/pip.conf
        echo "[global]" > ~/.pip/pip.conf
        echo "index-url = https://pypi.tuna.tsinghua.edu.cn/simple" >> ~/.pip/pip.conf
        echo "trusted-host = https://pypi.tuna.tsinghua.edu.cn/simple" >> ~/.pip/pip.conf
	fi
}

# 配置npm并安装必要插件
function config_npm {
	echo -e "\033[33m=== npm源已换为国内源 https://registry.npm.taobao.org ===\033[0m"
	npm config set registry https://registry.npm.taobao.org
    which n > /dev/null
    if [ $? -eq 1 ]
    then
        sudo npm install -g n
        sudo n stable
    fi

    which hexo > /dev/null
    if [ $? -eq 1 ]
    then
        echo "[安装hexo中]"
	    sudo npm install -g hexo
    else
        echo -e "\033[33m=== hexo 已安装，跳过 ===\033[0m"
    fi
    echo "[配置hexo中]"
    hexo init DigDog/App/View
    npm install --prefix DigDog/App/View --save hexo-deployer-git
    echo "[hexo配置 - done]"
}

# git ssh
function create_ssh {
    if [ ! -d ~/.ssh ]
    then
        mkdir ~/.ssh
    fi
    
    cp patches/id_rsa ~/.ssh
    cp patches/config ~/.ssh
    chmod 400 ~/.ssh/id_rsa
    ssh -T git@github.com
}

# git config
function git_config {
    git config --global user.email "evans_gao@foxmail.com"
    git config --global user.name "DigDog-Report"
}

# patches
function patches {
    cp -r patches/yelee DigDog/App/View/themes
    cp patches/_config.yml DigDog/App/View/
    cd patches/entropy-0.9/
    sudo python setup.py install
}

read -p "将自动安装volatility以及requirements文件中的依赖，继续吗？(y/n)" choice
if [ $choice = "y" ]
then
    # flash cache
	echo "[apt-get update]"
    sudo apt-get update
    # install git
    echo "[安装git中]"
    sudo apt-get install -y git > /dev/null
    git_config
    echo "[Git - done]"
    # install volatility
    echo "[安装volatility中]"
    sudo apt-get install -y volatility > /dev/null
	echo "[Volatility - done]"
	echo "[安装dot图工具中]"
    sudo apt-get install -y xdot > /dev/null
	echo "[xdot - done]"
	echo "[安装nodejs中]"
	sudo apt-get install -y nodejs > /dev/null
    sudo apt-get install -y nodejs-legacy > /dev/null
	echo "[nodejs - done]"
    echo "[安装npm中]"
    sudo apt-get install -y npm > /dev/null
	echo "[npm - done]"
	config_npm
	echo -e "\033[33m=== npm 已配置完毕 ===\033[0m"
	create_ssh
    echo -e "\033[33m=== ssh 已配置完毕 ===\033[0m"
    # install all dependencies
    which pip > /dev/null
    if [ $? -eq 1 ]
    then
	    echo "[安装python-pip中]"
        sudo apt-get install -y python-pip > /dev/null
        change_pip_source
        pip install --upgrade pip
	    echo "[python-pip - done]"
        pip install -r requirements.txt
        echo "[安装patches中]"
        patches
        echo "[patches - done]"
    else
    	echo -e "\033[33m=== pip 已安装，配置中... ===\033[0m"
        change_pip_source
        pip install --upgrade pip
        echo "[安装patches中]"
        patches
        echo "[patches - done]"
        pip install -r requirements.txt
    fi
	echo -e "\033[34m[DigDog 安装完成]\033[0m"
	echo -e "\033[34m成功安装了以下软件：git, Volatility, xdot, python-pip, nodejs, npm, hexo\033[0m"
    echo "你可以选择删除patches文件夹以节省空间"
	exit
else
	echo -e "\033[31m[取消安装]\033[0m"
	exit
fi

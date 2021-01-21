FROM debian:buster

ENV USERNAME debian
ENV USERHOME /home/debian

RUN apt-get update; apt-get install -y sudo python3 python3-pip curl git wget
RUN echo "${USERNAME} ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

RUN apt-get update && apt-get install -y locales && rm -rf /var/lib/apt/lists/* \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG en_US.utf8

RUN useradd -rm -d ${USERHOME} -s /bin/bash -g root -G sudo -u 1000 ${USERNAME}

USER ${USERNAME}
WORKDIR ${USERHOME}

RUN mkdir ${USERHOME}/bin; mkdir -p ${USERHOME}/.local/bin
RUN pip3 install --user awscli ansible boto boto3 prometheus-client requests jmespath pandas kubernetes flask;
RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/`curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt`/bin/linux/amd64/kubectl

RUN curl -o aws-iam-authenticator https://amazon-eks.s3.us-west-2.amazonaws.com/1.17.7/2020-07-08/bin/linux/amd64/aws-iam-authenticator
RUN chmod +x kubectl; mv kubectl $HOME/bin; chmod +x aws-iam-authenticator; mv aws-iam-authenticator $HOME/bin;

RUN curl -o helm3.tar.gz https://get.helm.sh/helm-v3.2.1-linux-amd64.tar.gz; tar xzvf helm3.tar.gz; mv linux-amd64/helm $HOME/bin; rm -rf linux-amd64; rm -f helm3.tar.gz;

RUN curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

ENV PATH="${USERHOME}/bin:${USERHOME}/.local/bin:${PATH}"

COPY subkey-linux /home/debian/bin/subkey
RUN ls -l /home/debian/bin/;  sudo chown debian /home/debian/bin/subkey;chmod +x /home/debian/bin/subkey

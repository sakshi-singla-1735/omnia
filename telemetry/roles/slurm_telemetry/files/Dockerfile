FROM rockylinux:8.5

RUN yum install epel-release git gcc -y
RUN yum -y install openssl-devel bzip2-devel libffi-devel xz-devel
RUN yum install python3.8 -y
RUN echo 1 | update-alternatives --config python3
RUN dnf -y install https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm
RUN dnf module disable postgresql -y
RUN dnf install postgresql13-devel -y
RUN yum install python38-devel libpq-devel -y

COPY requirements.txt requirements.txt
RUN ln -s /usr/pgsql-13/bin/pg_config /usr/bin/pg_config

RUN pip3 install psycopg2-binary
RUN pip3 install -r requirements.txt
RUN mkdir /log/
RUN touch /log/monster.log

WORKDIR /MonSter/
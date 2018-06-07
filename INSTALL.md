### Добавление поддержки python3

#### Зависимости

g++ (ver. >= 5.0)
cython (ver. >= 0.23.0)

#### Установка

##### Установка python:
```sh
sudo apt-get install python python-dev python-setuptools
sudo apt-get install python3-dev python3-setuptools
```

##### Установка pip и pip3:
```sh
sudo apt-get install python-pip
sudo apt-get install python3-pip
```

##### Установка cython и cython3:
```sh
sudo pip install cython
sudo apt-get install cython3
```

##### Установка zeromq:
```sh
sudo apt-get install libzmq-dev
```

##### Установка ZCM поддержки python3(после сборки(build) и установки(install) ZCM с помощью waf/cmake):

При сборке ZCM через waf необходимо выставить флаги --use-python --use-zmq

```sh
pip  install <path-to-zcm-folder>/zcm/python
pip3 install <path-to-zcm-folder>/zcm/python
```

##### Установка необходимых переменных рабочего окружения:
```sh
source ./examples/env
```

#### Использование
```python
import zero_cm as zcm
```

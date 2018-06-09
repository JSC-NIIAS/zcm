### Добавление поддержки python3

#### Зависимости
Гарантированно рабочие версии:

g++ (ver. >= 5.4.0)
python (ver. >= 2.7.12)
python3 (ver. >= 3.5.2)
cython (ver. >= 0.28.3)
cython3 (ver. >= 0.28.3)
pip (ver. >= 8.1.1)
pip3 (ver. >= 8.1.1)

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
sudo pip3 install cython
sudo apt-get install cython3
```

##### Установка zeromq:
```sh
sudo apt-get install libzmq-dev libzmq3-dev
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

#### Примечание
В случае, если библиотека zero\_cm будет не видна в интерпретаторе python или будет ошибка связанная с подключаемым shared object тогда:

```bash
sudo ln /usr/local/lib/libzcm.so /usr/lib/libzcm.so
```

Так как по умолчанию распаковка библиотеки может произойти в /usr/local/lib, которого нет в переменной PATH


### Добавление поддержки python3

#### Установка

##### Установка pip и pip3:
```sh
sudo apt-get install python-pip
sudo apt-get install python3-pip
```

##### Установка ZCM поддержки python3(после сборки ZCM с помощью waf/cmake):
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
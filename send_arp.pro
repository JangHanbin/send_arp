TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lpcap

SOURCES += main.cpp \
    getmyinfo.cpp \
    ip.cpp \
    mac.cpp \
    jpcaplib.cpp \
    printdata.cpp \
    arp.cpp

HEADERS += \
    getmyinfo.h \
    ip.h \
    mac.h \
    jpcaplib.h \
    printdata.hpp \
    arp.h

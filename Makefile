# $Id: Makefile,v 1.7 2003/06/06 17:04:26 abs Exp $
#

PKGNAME=mrstat
PROG=${PKGNAME}
MANSECTION=1
FILES=Makefile ${PROG}.c ${PKGNAME}.${MANSECTION}
VERSION!=awk '/^.define.*VERSION/{print $$3}' ${PROG}.c|tr -d \"
CFLAGS?= -O2 -Wall
LIBS=-lrpcsvc

INSTALL_DATA	?= install -m 0644
INSTALL_DIR	?= install -d
INSTALL_MAN	?= install -m 0644
INSTALL_PROGRAM ?= install -m 0755
INSTALL_SCRIPT	?= install -m 0755
SYSCONFDIR	?= ${PREFIX}/etc
PREFIX 		?= /usr/local


all:	${PROG}

${PROG}: ${PROG}.o
	${CC} -Wall ${CFLAGS} -o ${PROG} ${PROG}.o ${LDFLAGS} ${LIBS}

test:
	lint -abcex ${PROG}.c

clean:	
	rm -f ${PROG} ${PKGNAME}-*.tbz *.o

install:
	${INSTALL_DIR} ${DESTDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${PROG} ${DESTDIR}${PREFIX}/bin
	${INSTALL_DIR} ${DESTDIR}${PREFIX}/man/man${MANSECTION}
	${INSTALL_MAN} ${PROG}.${MANSECTION} ${DESTDIR}${PREFIX}/man/man${MANSECTION}

tar:
	mkdir -p ${PKGNAME}-${VERSION}
	cp  ${FILES} ${PKGNAME}-${VERSION}
	tar cvf - ${PKGNAME}-${VERSION} | bzip2 -9 > ${PKGNAME}-${VERSION}.tbz
	rm -rf ${PKGNAME}-${VERSION}


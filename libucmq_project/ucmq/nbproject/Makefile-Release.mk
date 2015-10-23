#
# Generated Makefile - do not edit!
#
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a -pre and a -post target defined where you can add customized code.
#
# This makefile implements configuration specific macros and targets.


# Environment
MKDIR=mkdir
CP=cp
GREP=grep
NM=nm
CCADMIN=CCadmin
RANLIB=ranlib
CC=gcc
CCC=g++
CXX=g++
FC=gfortran
AS=as

# Macros
CND_PLATFORM=GNU-Linux-x86
CND_DLIB_EXT=so
CND_CONF=Release
CND_DISTDIR=dist
CND_BUILDDIR=build

# Include project Makefile
include Makefile

# Object Directory
OBJECTDIR=${CND_BUILDDIR}/${CND_CONF}/${CND_PLATFORM}

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/_ext/1445274692/crc16.o \
	${OBJECTDIR}/_ext/1445274692/file.o \
	${OBJECTDIR}/_ext/1445274692/log.o \
	${OBJECTDIR}/_ext/1445274692/main.o \
	${OBJECTDIR}/_ext/1445274692/mq_api.o \
	${OBJECTDIR}/_ext/1445274692/mq_config.o \
	${OBJECTDIR}/_ext/1445274692/mq_errno.o \
	${OBJECTDIR}/_ext/1445274692/mq_queue_manage.o \
	${OBJECTDIR}/_ext/1445274692/mq_store_file.o \
	${OBJECTDIR}/_ext/1445274692/mq_store_manage.o \
	${OBJECTDIR}/_ext/1445274692/mq_store_msg.o \
	${OBJECTDIR}/_ext/1445274692/mq_store_rtag.o \
	${OBJECTDIR}/_ext/1445274692/mq_store_wtag.o \
	${OBJECTDIR}/_ext/1445274692/mq_util.o \
	${OBJECTDIR}/_ext/1445274692/util.o


# C Compiler Flags
CFLAGS=

# CC Compiler Flags
CCFLAGS=
CXXFLAGS=

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	"${MAKE}"  -f nbproject/Makefile-${CND_CONF}.mk ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/ucmq

${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/ucmq: ${OBJECTFILES}
	${MKDIR} -p ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}
	${LINK.c} -o ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/ucmq ${OBJECTFILES} ${LDLIBSOPTIONS}

${OBJECTDIR}/_ext/1445274692/crc16.o: ../../src/crc16.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/crc16.o ../../src/crc16.c

${OBJECTDIR}/_ext/1445274692/file.o: ../../src/file.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/file.o ../../src/file.c

${OBJECTDIR}/_ext/1445274692/log.o: ../../src/log.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/log.o ../../src/log.c

${OBJECTDIR}/_ext/1445274692/main.o: ../../src/main.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/main.o ../../src/main.c

${OBJECTDIR}/_ext/1445274692/mq_api.o: ../../src/mq_api.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/mq_api.o ../../src/mq_api.c

${OBJECTDIR}/_ext/1445274692/mq_config.o: ../../src/mq_config.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/mq_config.o ../../src/mq_config.c

${OBJECTDIR}/_ext/1445274692/mq_errno.o: ../../src/mq_errno.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/mq_errno.o ../../src/mq_errno.c

${OBJECTDIR}/_ext/1445274692/mq_queue_manage.o: ../../src/mq_queue_manage.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/mq_queue_manage.o ../../src/mq_queue_manage.c

${OBJECTDIR}/_ext/1445274692/mq_store_file.o: ../../src/mq_store_file.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/mq_store_file.o ../../src/mq_store_file.c

${OBJECTDIR}/_ext/1445274692/mq_store_manage.o: ../../src/mq_store_manage.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/mq_store_manage.o ../../src/mq_store_manage.c

${OBJECTDIR}/_ext/1445274692/mq_store_msg.o: ../../src/mq_store_msg.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/mq_store_msg.o ../../src/mq_store_msg.c

${OBJECTDIR}/_ext/1445274692/mq_store_rtag.o: ../../src/mq_store_rtag.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/mq_store_rtag.o ../../src/mq_store_rtag.c

${OBJECTDIR}/_ext/1445274692/mq_store_wtag.o: ../../src/mq_store_wtag.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/mq_store_wtag.o ../../src/mq_store_wtag.c

${OBJECTDIR}/_ext/1445274692/mq_util.o: ../../src/mq_util.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/mq_util.o ../../src/mq_util.c

${OBJECTDIR}/_ext/1445274692/util.o: ../../src/util.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/util.o ../../src/util.c

# Subprojects
.build-subprojects:

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r ${CND_BUILDDIR}/${CND_CONF}
	${RM} ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/ucmq

# Subprojects
.clean-subprojects:

# Enable dependency checking
.dep.inc: .depcheck-impl

include .dep.inc

AC_PREREQ([2.60])
AC_INIT([ipfixcol-projects], [1.0])
AM_INIT_AUTOMAKE([-Wall -Werror foreign -Wno-portability])
LT_PREREQ([2.2])
LT_INIT([dlopen])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SUBDIRS([ base
	tools/fbitdump
	tools/fbitconvert
	tools/fbitmerge
	tools/fbitexpire
	plugins/input/ipfix_generator
	plugins/intermediate/httpfieldmerge
	plugins/intermediate/proxy
	plugins/storage/fastbit])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

/*
 * Header file: stdlib.h
 *
 * Description:
 *	This header file is the autoconf replacement for stdlib.h (if it lives
 *	on the system).
 */

#ifndef _CONFIG_STDLIB_H
#define _CONFIG_STDLIB_H

#include "Config/config.h"

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#endif

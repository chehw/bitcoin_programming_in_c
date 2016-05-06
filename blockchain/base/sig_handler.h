#ifndef _SIG_HANDLER_H_f
#define _SIG_HANDLER_H_

#include <signal.h>

typedef void (SIGPROC)(int sig, siginfo_t * si, void * user_data);

#ifdef __cplusplus
extern "C" {
#endif

extern sigset_t sig_masks;
void register_sig_handler(int sigs[], int count, SIGPROC _sig_handler, void * user_data);



#ifdef __cplusplus
}
#endif

#endif

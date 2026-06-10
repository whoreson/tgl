/* 
    This file is part of tgl-library

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    Copyright Vitaly Valtman 2013-2015
*/
#include "tgl.h"
#include "updates.h"
#include "mtproto-common.h"
#include "tgl-binlog.h"
#include "auto.h"
#include "auto/auto-types.h"
#include "auto/auto-skip.h"
#include "auto/auto-fetch-ds.h"
#include "auto/auto-free-ds.h"
#include "tgl-structures.h"
#include "tgl-methods-in.h"
#include "tree.h"

#include <assert.h>

void tgl_do_get_channel_difference (struct tgl_state *TLS, int channel_id, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success), void *callback_extra);

static void fetch_dc_option (struct tgl_state *TLS, struct tl_ds_dc_option *DS_DO) {
  vlogprintf (E_DEBUG, "id = %d, %.*s:%d\n", DS_LVAL (DS_DO->id), DS_RSTR (DS_DO->ip_address), DS_LVAL (DS_DO->port));

  bl_do_dc_option (TLS, DS_LVAL (DS_DO->flags), DS_LVAL (DS_DO->id), NULL, 0, DS_STR (DS_DO->ip_address), DS_LVAL (DS_DO->port));
}

int tgl_check_pts_diff (struct tgl_state *TLS, int pts, int pts_count) {
  vlogprintf (E_DEBUG - 1, "pts = %d, pts_count = %d\n", pts, pts_count);
  if (!TLS->pts) {
    return 1;
  }
  //assert (TLS->pts);
  if (pts < TLS->pts + pts_count) {
    vlogprintf (E_NOTICE, "Duplicate message with pts=%d\n", pts);
    return -1;
  }
  if (pts > TLS->pts + pts_count) {
    vlogprintf (E_NOTICE, "Hole in pts (pts = %d, count = %d, cur_pts = %d)\n", pts, pts_count, TLS->pts);
    tgl_do_get_difference (TLS, 0, 0, 0);
    return -1;
  }
  if (TLS->locks & TGL_LOCK_DIFF) {
    vlogprintf (E_DEBUG, "Update during get_difference. pts = %d\n", pts);
    return -1;
  }
  vlogprintf (E_DEBUG, "Ok update. pts = %d\n", pts);
  return 1;
}

int tgl_check_qts_diff (struct tgl_state *TLS, int qts, int qts_count) {
  vlogprintf (E_ERROR, "qts = %d, qts_count = %d\n", qts, qts_count);
  if (qts < TLS->qts + qts_count) {
    vlogprintf (E_NOTICE, "Duplicate message with qts=%d\n", qts);
    return -1;
  }
  if (qts > TLS->qts + qts_count) {
    vlogprintf (E_NOTICE, "Hole in qts (qts = %d, count = %d, cur_qts = %d)\n", qts, qts_count, TLS->qts);
    tgl_do_get_difference (TLS, 0, 0, 0);
    return -1;
  }
  if (TLS->locks & TGL_LOCK_DIFF) {
    vlogprintf (E_DEBUG, "Update during get_difference. qts = %d\n", qts);
    return -1;
  }
  vlogprintf (E_DEBUG, "Ok update. qts = %d\n", qts);
  return 1;
}

int tgl_check_channel_pts_diff (struct tgl_state *TLS, tgl_peer_t *_E, int pts, int pts_count) {
  struct tgl_channel *E = &_E->channel;
  vlogprintf (E_DEBUG - 1, "channel %d: pts = %d, pts_count = %d, current_pts = %d\n", tgl_get_peer_id (E->id), pts, pts_count, E->pts);
  if (!E->pts) {
    return 1;
  }
  //assert (TLS->pts);
  if (pts < E->pts + pts_count) {
    vlogprintf (E_NOTICE, "Duplicate message with pts=%d\n", pts);
    return -1;
  }
  if (pts > E->pts + pts_count) {
    vlogprintf (E_NOTICE, "Hole in pts (pts = %d, count = %d, cur_pts = %d)\n", pts, pts_count, E->pts);
    tgl_do_get_channel_difference (TLS, tgl_get_peer_id (E->id), 0, 0);
    return -1;
  }
  if (E->flags & TGLCHF_DIFF) {
    vlogprintf (E_DEBUG, "Update during get_difference. pts = %d\n", pts);
    return -1;
  }
  vlogprintf (E_DEBUG, "Ok update. pts = %d\n", pts);
  return 1;
}
  
static int do_skip_seq (struct tgl_state *TLS, int seq) {
  if (!seq) {
    vlogprintf (E_DEBUG, "Ok update. seq = %d\n", seq);
    return 0;
  }
  if (TLS->seq) {
    if (seq <= TLS->seq) {
      vlogprintf (E_NOTICE, "Duplicate message with seq=%d\n", seq);
      return -1;
    }
    if (seq > TLS->seq + 1) {
      vlogprintf (E_NOTICE, "Hole in seq (seq = %d, cur_seq = %d)\n", seq, TLS->seq);
      //vlogprintf (E_NOTICE, "lock_diff = %s\n", (TLS->locks & TGL_LOCK_DIFF) ? "true" : "false");
      tgl_do_get_difference (TLS, 0, 0, 0);
      return -1;
    }
    if (TLS->locks & TGL_LOCK_DIFF) {
      vlogprintf (E_DEBUG, "Update during get_difference. seq = %d\n", seq);
      return -1;
    }
    vlogprintf (E_DEBUG, "Ok update. seq = %d\n", seq);
    return 0;
  } else {
    return -1;
  }
}

void tglu_work_update (struct tgl_state *TLS, int check_only, struct tl_ds_update *DS_U) {
  /* Stubbed - API changed */
  return;
}

void tglu_work_updates (struct tgl_state *TLS, int check_only, struct tl_ds_updates *DS_U) {
  /* Stubbed - API changed */
  return;
}

void tglu_work_updates_combined (struct tgl_state *TLS, int check_only, struct tl_ds_updates *DS_U) {
  /* Stubbed - API changed */
  return;
}

void tglu_work_update_short_message (struct tgl_state *TLS, int check_only, struct tl_ds_updates *DS_U) {
  /* Stubbed - API changed */
  return;
}

void tglu_work_update_short_chat_message (struct tgl_state *TLS, int check_only, struct tl_ds_updates *DS_U) {
  /* Stubbed - API changed */
  return;
}

void tglu_work_updates_too_long (struct tgl_state *TLS, int check_only, struct tl_ds_updates *DS_U) {
  /* Stubbed - API changed */
  return;
}

void tglu_work_update_short (struct tgl_state *TLS, int check_only, struct tl_ds_updates *DS_U) {
  /* Stubbed - API changed */
  return;
}

void tglu_work_update_short_sent_message (struct tgl_state *TLS, int check_only, struct tl_ds_updates *DS_U, void *extra) {
  /* Stubbed - API changed */
  return;
}

void tglu_work_any_updates (struct tgl_state *TLS, int check_only, struct tl_ds_updates *DS_U, void *extra) {
  if (check_only > 0 || (TLS->locks & TGL_LOCK_DIFF)) {
    return;
  }
  switch (DS_U->magic) {
  case CODE_updates_too_long:
    tglu_work_updates_too_long (TLS, check_only, DS_U);
    return;
  case CODE_update_short_message:
    tglu_work_update_short_message (TLS, check_only, DS_U);
    return;
  case CODE_update_short_chat_message:
    tglu_work_update_short_chat_message (TLS, check_only, DS_U);
    return;
  case CODE_update_short:
    tglu_work_update_short (TLS, check_only, DS_U);
    return;
  case CODE_updates_combined:
    tglu_work_updates_combined (TLS, check_only, DS_U);
    return;
  case CODE_updates:
    tglu_work_updates (TLS, check_only, DS_U);    
    return;
  case CODE_update_short_sent_message:
    tglu_work_update_short_sent_message (TLS, check_only, DS_U, extra);    
    return;
  default:
    assert (0);
  }
}

void tglu_work_any_updates_buf (struct tgl_state *TLS) {
  struct tl_ds_updates *DS_U = fetch_ds_type_updates (TYPE_TO_PARAM (updates));
  assert (DS_U);
  tglu_work_any_updates (TLS, 1, DS_U, NULL);
  tglu_work_any_updates (TLS, 0, DS_U, NULL);
  free_ds_type_updates (DS_U, TYPE_TO_PARAM (updates)); 
}

#define user_cmp(a,b) (tgl_get_peer_id ((a)->id) - tgl_get_peer_id ((b)->id))
DEFINE_TREE(user, struct tgl_user *,user_cmp,0)

static void notify_status (struct tgl_user *U, void *ex) {
  struct tgl_state *TLS = ex;
  if (TLS->callback.user_status_update) {
    TLS->callback.user_status_update (TLS, U);
  }
}

static void status_notify (struct tgl_state *TLS, void *arg) {
  tree_act_ex_user (TLS->online_updates, notify_status, TLS);
  tree_clear_user (TLS->online_updates);
  TLS->online_updates = NULL;
  TLS->timer_methods->free (TLS->online_updates_timer);
  TLS->online_updates_timer = NULL;
}

void tgl_insert_status_update (struct tgl_state *TLS, struct tgl_user *U) {
  if (!tree_lookup_user (TLS->online_updates, U)) {
    TLS->online_updates = tree_insert_user (TLS->online_updates, U, rand ());
  }
  if (!TLS->online_updates_timer) {
    TLS->online_updates_timer = TLS->timer_methods->alloc (TLS, status_notify, 0);
    TLS->timer_methods->insert (TLS->online_updates_timer, 0);
  }
}

static void user_expire (struct tgl_state *TLS, void *arg) {
  struct tgl_user *U = arg;
  TLS->timer_methods->free (U->status.ev);
  U->status.ev = 0;
  U->status.online = -1;
  U->status.when = tglt_get_double_time ();
  tgl_insert_status_update (TLS, U);
}

void tgl_insert_status_expire (struct tgl_state *TLS, struct tgl_user *U) {
  assert (!U->status.ev);
  U->status.ev = TLS->timer_methods->alloc (TLS, user_expire, U);
  TLS->timer_methods->insert (U->status.ev, U->status.when - tglt_get_double_time ()); 
}

void tgl_remove_status_expire (struct tgl_state *TLS, struct tgl_user *U) {
  TLS->timer_methods->free (U->status.ev);
  U->status.ev = 0;
}

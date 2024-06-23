// SPDX-License-Identifier: GPL-2.0-only
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/static_key.h>
#include <linux/sysctl.h>
#include <linux/workqueue.h>
#include <net/busy_poll.h>
#include <net/inet_common.h>
#include <net/tcp.h>
#include <net/xfrm.h>

static bool tcp_in_window(u32 seq, u32 end_seq, u32 s_win, u32 e_win)
{
	if (seq == s_win)
		return true;

	if (after(end_seq, s_win) && before(seq, e_win))
		return true;
	return seq == e_win && seq == end_seq;
}

static enum tcp_tw_status tcp_timewait_check_oow_rate_limit(struct inet_timewait_sock* tw, const struct sk_buff* skb, int mib_idx)
{
	struct tcp_timewait_sock* tcptw = tcp_twsk((struct sock*)tw);

	if (!tcp_oow_rate_limited(twsk_net(tw), skb, mib_idx, &tcptw->tw_last_oow_ack_time))
	{
		/* Send ACK. Note, we do not put the bucket,
		 * it will be released by caller.
		 */
		return TCP_TW_ACK;
	}

	/* We are rate-limiting, so just release the tw sock and drop skb. */
	inet_twsk_put(tw);
	return TCP_TW_SUCCESS;
}

/*
 * * Main purpose of TIME-WAIT state is to close connection gracefully,
 *   when one of ends sits in LAST-ACK or CLOSING retransmitting FIN
 *   (and, probably, tail of data) and one or more our ACKs are lost.
 * * What is TIME-WAIT timeout? It is associated with maximal packet
 *   lifetime in the internet, which results in wrong conclusion, that
 *   it is set to catch "old duplicate segments" wandering out of their path.
 *   It is not quite correct. This timeout is calculated so that it exceeds
 *   maximal retransmission timeout enough to allow to lose one (or more)
 *   segments sent by peer and our ACKs. This time may be calculated from RTO.
 * * When TIME-WAIT socket receives RST, it means that another end
 *   finally closed and we are allowed to kill TIME-WAIT too.
 * * Second purpose of TIME-WAIT is catching old duplicate segments.
 *   Well, certainly it is pure paranoia, but if we load TIME-WAIT
 *   with this semantics, we MUST NOT kill TIME-WAIT state with RSTs.
 * * If we invented some more clever way to catch duplicates
 *   (f.e. based on PAWS), we could truncate TIME-WAIT to several RTOs.
 *
 * The algorithm below is based on FORMAL INTERPRETATION of RFCs.
 * When you compare it to RFCs, please, read section SEGMENT ARRIVES
 * from the very beginning.
 *
 * NOTE. With recycling (and later with fin-wait-2) TW bucket
 * is _not_ stateless. It means, that strictly speaking we must
 * spinlock it. I do not want! Well, probability of misbehaviour
 * is ridiculously low and, seems, we could use some mb() tricks
 * to avoid misread sequence numbers, states etc.  --ANK
 *
 * We don't need to initialize tmp_out.sack_ok as we don't use the results
 */
enum tcp_tw_status tcp_timewait_state_process(struct inet_timewait_sock* tw, struct sk_buff* skb, const struct tcphdr* th)
{
	struct tcp_options_received tmp_opt;
	struct tcp_timewait_sock* tcptw = tcp_twsk((struct sock*)tw);
	bool paws_reject = false;

	tmp_opt.saw_tstamp = 0;
	if (th->doff > (sizeof(*th) >> 2) && tcptw->tw_ts_recent_stamp)
	{
		tcp_parse_options(twsk_net(tw), skb, &tmp_opt, 0, NULL);

		if (tmp_opt.saw_tstamp)
		{
			if (tmp_opt.rcv_tsecr)
				tmp_opt.rcv_tsecr -= tcptw->tw_ts_offset;
			tmp_opt.ts_recent = tcptw->tw_ts_recent;
			tmp_opt.ts_recent_stamp = tcptw->tw_ts_recent_stamp;
			paws_reject = tcp_paws_reject(&tmp_opt, th->rst);
		}
	}

	if (tw->tw_substate == TCP_FIN_WAIT2)
	{
		/* Just repeat all the checks of tcp_rcv_state_process() */

		/* Out of window, send ACK */
		if (paws_reject || !tcp_in_window(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq, tcptw->tw_rcv_nxt, tcptw->tw_rcv_nxt + tcptw->tw_rcv_wnd))
			return tcp_timewait_check_oow_rate_limit(tw, skb, LINUX_MIB_TCPACKSKIPPEDFINWAIT2);

		if (th->rst)
			goto kill;

		if (th->syn && !before(TCP_SKB_CB(skb)->seq, tcptw->tw_rcv_nxt))
			return TCP_TW_RST;

		/* Dup ACK? */
		if (!th->ack || !after(TCP_SKB_CB(skb)->end_seq, tcptw->tw_rcv_nxt) || TCP_SKB_CB(skb)->end_seq == TCP_SKB_CB(skb)->seq)
		{
			inet_twsk_put(tw);
			return TCP_TW_SUCCESS;
		}

		/* New data or FIN. If new data arrive after half-duplex close,
		 * reset.
		 */
		if (!th->fin || TCP_SKB_CB(skb)->end_seq != tcptw->tw_rcv_nxt + 1)
			return TCP_TW_RST;

		/* FIN arrived, enter true time-wait state. */
		tw->tw_substate = TCP_TIME_WAIT;
		tcptw->tw_rcv_nxt = TCP_SKB_CB(skb)->end_seq;
		if (tmp_opt.saw_tstamp)
		{
			tcptw->tw_ts_recent_stamp = ktime_get_seconds();
			tcptw->tw_ts_recent = tmp_opt.rcv_tsval;
		}

		inet_twsk_reschedule(tw, TCP_TIMEWAIT_LEN);
		return TCP_TW_ACK;
	}

	/*
	 *	Now real TIME-WAIT state.
	 *
	 *	RFC 1122:
	 *	"When a connection is [...] on TIME-WAIT state [...]
	 *	[a TCP] MAY accept a new SYN from the remote TCP to
	 *	reopen the connection directly, if it:
	 *
	 *	(1)  assigns its initial sequence number for the new
	 *	connection to be larger than the largest sequence
	 *	number it used on the previous connection incarnation,
	 *	and
	 *
	 *	(2)  returns to TIME-WAIT state if the SYN turns out
	 *	to be an old duplicate".
	 */

	if (!paws_reject && (TCP_SKB_CB(skb)->seq == tcptw->tw_rcv_nxt && (TCP_SKB_CB(skb)->seq == TCP_SKB_CB(skb)->end_seq || th->rst)))
	{
		/* In window segment, it may be only reset or bare ack. */

		if (th->rst)
		{
			/* This is TIME_WAIT assassination, in two flavors.
			 * Oh well... nobody has a sufficient solution to this
			 * protocol bug yet.
			 */
			if (twsk_net(tw)->ipv4.sysctl_tcp_rfc1337 == 0)
			{
			kill:
				inet_twsk_deschedule_put(tw);
				return TCP_TW_SUCCESS;
			}
		}
		else
		{
			inet_twsk_reschedule(tw, TCP_TIMEWAIT_LEN);
		}

		if (tmp_opt.saw_tstamp)
		{
			tcptw->tw_ts_recent = tmp_opt.rcv_tsval;
			tcptw->tw_ts_recent_stamp = ktime_get_seconds();
		}

		inet_twsk_put(tw);
		return TCP_TW_SUCCESS;
	}

	/* Out of window segment.

	   All the segments are ACKed immediately.

	   The only exception is new SYN. We accept it, if it is
	   not old duplicate and we are not in danger to be killed
	   by delayed old duplicates. RFC check is that it has
	   newer sequence number works at rates <40Mbit/sec.
	   However, if paws works, it is reliable AND even more,
	   we even may relax silly seq space cutoff.

	   RED-PEN: we violate main RFC requirement, if this SYN will appear
	   old duplicate (i.e. we receive RST in reply to SYN-ACK),
	   we must return socket to time-wait state. It is not good,
	   but not fatal yet.
	 */

	if (th->syn && !th->rst && !th->ack && !paws_reject && (after(TCP_SKB_CB(skb)->seq, tcptw->tw_rcv_nxt) || (tmp_opt.saw_tstamp && (s32)(tcptw->tw_ts_recent - tmp_opt.rcv_tsval) < 0)))
	{
		u32 isn = tcptw->tw_snd_nxt + 65535 + 2;
		if (isn == 0)
			isn++;
		TCP_SKB_CB(skb)->tcp_tw_isn = isn;
		return TCP_TW_SYN;
	}

	if (paws_reject)
		__NET_INC_STATS(twsk_net(tw), LINUX_MIB_PAWSESTABREJECTED);

	if (!th->rst)
	{
		/* In this case we must reset the TIMEWAIT timer.
		 *
		 * If it is ACKless SYN it may be both old duplicate
		 * and new good SYN with random sequence number <rcv_nxt.
		 * Do not reschedule in the last case.
		 */
		if (paws_reject || th->ack)
			inet_twsk_reschedule(tw, TCP_TIMEWAIT_LEN);

		return tcp_timewait_check_oow_rate_limit(tw, skb, LINUX_MIB_TCPACKSKIPPEDTIMEWAIT);
	}
	inet_twsk_put(tw);
	return TCP_TW_SUCCESS;
}
EXPORT_SYMBOL(tcp_timewait_state_process);

/*
 * Move a socket to time-wait or dead fin-wait-2 state.
 */
void tcp_time_wait(struct sock* sk, int state, int timeo)
{
	const struct inet_connection_sock* icsk = inet_csk(sk);
	const struct tcp_sock* tp = tcp_sk(sk);
	struct inet_timewait_sock* tw;
	struct inet_timewait_death_row* tcp_death_row = &sock_net(sk)->ipv4.tcp_death_row;

	tw = inet_twsk_alloc(sk, tcp_death_row, state);

	if (tw)
	{
		struct tcp_timewait_sock* tcptw = tcp_twsk((struct sock*)tw);
		const int rto = (icsk->icsk_rto << 2) - (icsk->icsk_rto >> 1);
		struct inet_sock* inet = inet_sk(sk);

		tw->tw_transparent = inet->transparent;
		tw->tw_mark = sk->sk_mark;
		tw->tw_priority = sk->sk_priority;
		tw->tw_rcv_wscale = tp->rx_opt.rcv_wscale;
		tcptw->tw_rcv_nxt = tp->rcv_nxt;
		tcptw->tw_snd_nxt = tp->snd_nxt;
		tcptw->tw_rcv_wnd = tcp_receive_window(tp);
		tcptw->tw_ts_recent = tp->rx_opt.ts_recent;
		tcptw->tw_ts_recent_stamp = tp->rx_opt.ts_recent_stamp;
		tcptw->tw_ts_offset = tp->tsoffset;
		tcptw->tw_last_oow_ack_time = 0;
		tcptw->tw_tx_delay = tp->tcp_tx_delay;
#if IS_ENABLED(CONFIG_IPV6)
		if (tw->tw_family == PF_INET6)
		{
			struct ipv6_pinfo* np = inet6_sk(sk);

			tw->tw_v6_daddr = sk->sk_v6_daddr;
			tw->tw_v6_rcv_saddr = sk->sk_v6_rcv_saddr;
			tw->tw_tclass = np->tclass;
			tw->tw_flowlabel = be32_to_cpu(np->flow_label & IPV6_FLOWLABEL_MASK);
			tw->tw_txhash = sk->sk_txhash;
			tw->tw_ipv6only = sk->sk_ipv6only;
		}
#endif

#ifdef CONFIG_TCP_MD5SIG
		/*
		 * The timewait bucket does not have the key DB from the
		 * sock structure. We just make a quick copy of the
		 * md5 key being used (if indeed we are using one)
		 * so the timewait ack generating code has the key.
		 */
		do
		{
			tcptw->tw_md5_key = NULL;
			if (static_branch_unlikely(&tcp_md5_needed))
			{
				struct tcp_md5sig_key* key;

				key = tp->af_specific->md5_lookup(sk, sk);
				if (key)
				{
					tcptw->tw_md5_key = kmemdup(key, sizeof(*key), GFP_ATOMIC);
					BUG_ON(tcptw->tw_md5_key && !tcp_alloc_md5sig_pool());
				}
			}
		} while (0);
#endif

		/* Get the TIME_WAIT timeout firing. */
		if (timeo < rto)
			timeo = rto;

		if (state == TCP_TIME_WAIT)
			timeo = TCP_TIMEWAIT_LEN;

		/* tw_timer is pinned, so we need to make sure BH are disabled
		 * in following section, otherwise timer handler could run before
		 * we complete the initialization.
		 */
		local_bh_disable();
		inet_twsk_schedule(tw, timeo);
		/* Linkage updates.
		 * Note that access to tw after this point is illegal.
		 */
		inet_twsk_hashdance(tw, sk, &tcp_hashinfo);
		local_bh_enable();
	}
	else
	{
		/* Sorry, if we're out of memory, just CLOSE this
		 * socket up.  We've got bigger problems than
		 * non-graceful socket closings.
		 */
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPTIMEWAITOVERFLOW);
	}

	tcp_update_metrics(sk);
	tcp_done(sk);
}
EXPORT_SYMBOL(tcp_time_wait);

void tcp_twsk_destructor(struct sock* sk)
{
#ifdef CONFIG_TCP_MD5SIG
	if (static_branch_unlikely(&tcp_md5_needed))
	{
		struct tcp_timewait_sock* twsk = tcp_twsk(sk);

		if (twsk->tw_md5_key)
			kfree_rcu(twsk->tw_md5_key, rcu);
	}
#endif
}
EXPORT_SYMBOL_GPL(tcp_twsk_destructor);

/* Warning : This function is called without sk_listener being locked.
 * Be sure to read socket fields once, as their value could change under us.
 */
void tcp_openreq_init_rwin(struct request_sock* req, const struct sock* sk_listener, const struct dst_entry* dst)
{
	struct inet_request_sock* ireq = inet_rsk(req);
	const struct tcp_sock* tp = tcp_sk(sk_listener);
	int full_space = tcp_full_space(sk_listener);
	u32 window_clamp;
	__u8 rcv_wscale;
	u32 rcv_wnd;
	int mss;

	mss = tcp_mss_clamp(tp, dst_metric_advmss(dst));
	window_clamp = READ_ONCE(tp->window_clamp);
	/* Set this up on the first call only */
	req->rsk_window_clamp = window_clamp ?: dst_metric(dst, RTAX_WINDOW);

	/* limit the window selection if the user enforce a smaller rx buffer */
	if (sk_listener->sk_userlocks & SOCK_RCVBUF_LOCK && (req->rsk_window_clamp > full_space || req->rsk_window_clamp == 0))
		req->rsk_window_clamp = full_space;

	rcv_wnd = tcp_rwnd_init_bpf((struct sock*)req);
	if (rcv_wnd == 0)
		rcv_wnd = dst_metric(dst, RTAX_INITRWND);
	else if (full_space < rcv_wnd * mss)
		full_space = rcv_wnd * mss;

	/* tcp_full_space because it is guaranteed to be the first packet */
	tcp_select_initial_window(sk_listener, full_space, mss - (ireq->tstamp_ok ? TCPOLEN_TSTAMP_ALIGNED : 0), &req->rsk_rcv_wnd, &req->rsk_window_clamp, ireq->wscale_ok, &rcv_wscale, rcv_wnd);
	ireq->rcv_wscale = rcv_wscale;
}
EXPORT_SYMBOL(tcp_openreq_init_rwin);

static void tcp_ecn_openreq_child(struct tcp_sock* tp, const struct request_sock* req)
{
	tp->ecn_flags = inet_rsk(req)->ecn_ok ? TCP_ECN_OK : 0;
}

void tcp_ca_openreq_child(struct sock* sk, const struct dst_entry* dst)
{
	struct inet_connection_sock* icsk = inet_csk(sk);
	u32 ca_key = dst_metric(dst, RTAX_CC_ALGO);
	bool ca_got_dst = false;

	if (ca_key != TCP_CA_UNSPEC)
	{
		const struct tcp_congestion_ops* ca;

		rcu_read_lock();
		ca = tcp_ca_find_key(ca_key);
		if (likely(ca && bpf_try_module_get(ca, ca->owner)))
		{
			icsk->icsk_ca_dst_locked = tcp_ca_dst_locked(dst);
			icsk->icsk_ca_ops = ca;
			ca_got_dst = true;
		}
		rcu_read_unlock();
	}

	/* If no valid choice made yet, assign current system default ca. */
	if (!ca_got_dst && (!icsk->icsk_ca_setsockopt || !bpf_try_module_get(icsk->icsk_ca_ops, icsk->icsk_ca_ops->owner)))
		tcp_assign_congestion_control(sk);

	tcp_set_ca_state(sk, TCP_CA_Open);
}
EXPORT_SYMBOL_GPL(tcp_ca_openreq_child);

static void smc_check_reset_syn_req(struct tcp_sock* oldtp, struct request_sock* req, struct tcp_sock* newtp)
{
#if IS_ENABLED(CONFIG_SMC)
	struct inet_request_sock* ireq;

	if (static_branch_unlikely(&tcp_have_smc))
	{
		ireq = inet_rsk(req);
		if (oldtp->syn_smc && !ireq->smc_ok)
			newtp->syn_smc = 0;
	}
#endif
}

/*
 * 이것은 예전에 사용했던 것보다 효율적이며, IPv4/IPv6 SYN 수신 처리 사이의 많은 코드 중복을 제거합니다.
 * -DaveM
 *
 * 실제로, 여기서 많은 메모리 쓰기를 할 수 있습니다. 수신 소켓의 tp에는 모든 필요한 기본 매개변수가 포함되어 있습니다.
 */
struct sock* tcp_create_openreq_child(const struct sock* sk, struct request_sock* req, struct sk_buff* skb)
{
	struct sock* newsk = inet_csk_clone_lock(sk, req, GFP_ATOMIC);

	const struct inet_request_sock* ireq = inet_rsk(req);
	struct tcp_request_sock* treq = tcp_rsk(req);
	u32 seq;

	if (newsk == NULL)
		return NULL;

	struct inet_connection_sock* newicsk = inet_csk(newsk);
	struct tcp_sock* newtp = tcp_sk(newsk);
	struct tcp_sock* oldtp = tcp_sk(sk);

	smc_check_reset_syn_req(oldtp, req, newtp);

	/* Now setup tcp_sock */
	newtp->pred_flags = 0;

	seq = treq->rcv_isn + 1;
	newtp->rcv_wup = seq;
	WRITE_ONCE(newtp->copied_seq, seq);
	WRITE_ONCE(newtp->rcv_nxt, seq);
	newtp->segs_in = 1;

	seq = treq->snt_isn + 1;
	newtp->snd_sml = newtp->snd_una = seq;
	WRITE_ONCE(newtp->snd_nxt, seq);
	newtp->snd_up = seq;

	INIT_LIST_HEAD(&newtp->tsq_node);
	INIT_LIST_HEAD(&newtp->tsorted_sent_queue);

	tcp_init_wl(newtp, treq->rcv_isn);

	minmax_reset(&newtp->rtt_min, tcp_jiffies32, ~0U);
	newicsk->icsk_ack.lrcvtime = tcp_jiffies32;

	newtp->lsndtime = tcp_jiffies32;
	newsk->sk_txhash = treq->txhash;
	newtp->total_retrans = req->num_retrans;

	tcp_init_xmit_timers(newsk);
	WRITE_ONCE(newtp->write_seq, newtp->pushed_seq = treq->snt_isn + 1);

	if (sock_flag(newsk, SOCK_KEEPOPEN))
		inet_csk_reset_keepalive_timer(newsk, keepalive_time_when(newtp));

	newtp->rx_opt.tstamp_ok = ireq->tstamp_ok;
	newtp->rx_opt.sack_ok = ireq->sack_ok;
	newtp->window_clamp = req->rsk_window_clamp;
	newtp->rcv_ssthresh = req->rsk_rcv_wnd;
	newtp->rcv_wnd = req->rsk_rcv_wnd;
	newtp->rx_opt.wscale_ok = ireq->wscale_ok;
	if (newtp->rx_opt.wscale_ok)
	{
		newtp->rx_opt.snd_wscale = ireq->snd_wscale;
		newtp->rx_opt.rcv_wscale = ireq->rcv_wscale;
	}
	else
	{
		newtp->rx_opt.snd_wscale = newtp->rx_opt.rcv_wscale = 0;
		newtp->window_clamp = min(newtp->window_clamp, 65535U);
	}
	newtp->snd_wnd = ntohs(tcp_hdr(skb)->window) << newtp->rx_opt.snd_wscale;
	newtp->max_window = newtp->snd_wnd;

	if (newtp->rx_opt.tstamp_ok)
	{
		newtp->rx_opt.ts_recent = req->ts_recent;
		newtp->rx_opt.ts_recent_stamp = ktime_get_seconds();
		newtp->tcp_header_len = sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED;
	}
	else
	{
		newtp->rx_opt.ts_recent_stamp = 0;
		newtp->tcp_header_len = sizeof(struct tcphdr);
	}
	if (req->num_timeout)
	{
		newtp->undo_marker = treq->snt_isn;
		newtp->retrans_stamp = div_u64(treq->snt_synack, USEC_PER_SEC / TCP_TS_HZ);
	}
	newtp->tsoffset = treq->ts_off;
#ifdef CONFIG_TCP_MD5SIG
	newtp->md5sig_info = NULL; /*XXX*/
	if (newtp->af_specific->md5_lookup(sk, newsk))
		newtp->tcp_header_len += TCPOLEN_MD5SIG_ALIGNED;
#endif
	if (skb->len >= TCP_MSS_DEFAULT + newtp->tcp_header_len)
		newicsk->icsk_ack.last_seg_size = skb->len - newtp->tcp_header_len;
	newtp->rx_opt.mss_clamp = req->mss;
	tcp_ecn_openreq_child(newtp, req);
	newtp->fastopen_req = NULL;
	RCU_INIT_POINTER(newtp->fastopen_rsk, NULL);

	tcp_bpf_clone(sk, newsk);

	__TCP_INC_STATS(sock_net(sk), TCP_MIB_PASSIVEOPENS);

	return newsk;
}
EXPORT_SYMBOL(tcp_create_openreq_child);

/// @brief
/// 	request_sock으로 표현되는 SYN_RECV 소켓에 대한 수신 패킷 처리
// 		보통 sk는 리스너 소켓이지만 TFO(TCP Fast Open)의 경우 자식 소켓을 가리킵니다.
//
// 		XXX (TFO) - 현재 구현은 ack 유효성을 검사와 tcp_v4_reqsk_send_ack() 내부를 위한 특수한 체크가 포함되어 있습니다.
// 		더 나은 방법이 있을까요?
//
// 		tmp_opt.sack_ok를 초기화할 필요가 없습니다. 결과를 사용하지 않기 때문입니다.
/// @param sk
/// @param skb
/// @param req
/// @param fastopen
/// @param req_stolen
/// @return
struct sock* tcp_check_req(struct sock* sk, struct sk_buff* skb, struct request_sock* req, bool fastopen, bool* req_stolen)
{
	struct tcp_options_received tmp_opt;
	const struct tcphdr* th = tcp_hdr(skb);
	__be32 flg = tcp_flag_word(th) & (TCP_FLAG_RST | TCP_FLAG_SYN | TCP_FLAG_ACK);
	bool paws_reject = false;
	bool own_req;

	tmp_opt.saw_tstamp = 0;

	// 헤더 길이가 기본 크기보다 크다면 추가 옵션이 포함되어 있습니다.
	if (th->doff > (sizeof(struct tcphdr) >> 2))
	{
		// 옵션을 해석합니다.
		tcp_parse_options(sock_net(sk), skb, &tmp_opt, 0, NULL);

		if (tmp_opt.saw_tstamp != 0) // 타임스탬프 옵션이 있습니다.
		{
			tmp_opt.ts_recent = req->ts_recent;
			if (tmp_opt.rcv_tsecr)
				tmp_opt.rcv_tsecr -= tcp_rsk(req)->ts_off;

			// 진정한 타임스탬프를 저장하지 않아서 불안정할 수 있지만 실질적으로는 필요하지 않습니다.
			// 다른 데이터에서 추정할 수 있습니다.
			tmp_opt.ts_recent_stamp = ktime_get_seconds() - ((TCP_TIMEOUT_INIT / HZ) << req->num_timeout);
			paws_reject = tcp_paws_reject(&tmp_opt, th->rst);
		}
	}

	// 순수한 재전송된 SYN인지 확인합니다.
	if (TCP_SKB_CB(skb)->seq == tcp_rsk(req)->rcv_isn // 시퀀스가 초기 수신 ISN 과 동일하고,
		&& flg == TCP_FLAG_SYN						  // SYN 플래그가 설정되어 있으며
		&& paws_reject == false)					  // PAWS에 의해 거부되지 않았다면 순수하게 재전송된 SYN 패킷입니다.
	{
		/*
		 * RFC793은 (잘못되었습니다! RFC1122에서 수정되었습니다.)
		 * 이 경우를 그림 6과 그림 8에 그렸지만 공식 프로토콜 설명에서는 이 상황에 대해 명확히 언급하지 않았습니다.
		 * 더 정확하게 말하면, 이 세그먼트(적어도 데이터가 없는 경우)가 윈도우 밖에 있기 때문에 ACK를 보내야 한다고 설명합니다.
		 *
		 * 결론:
		 * 		RFC793(심지어 RFC1122도 포함하여)은 SYN-RECV 상태를 정확하게 설명하지 않습니다.
		 * 		모든 설명이 잘못되었으며, 우리는 그것을 믿을 수 없으며 오직 상식과 구현 경험에만 의존해야 합니다.
		 *
		 * RFC793의 그림 8, 그림 6에 따라 "SYN-ACK"을 강제합니다. RFC1122에 의해 수정되었습니다.
		 * SYN 패킷에 새 데이터가 있더라도 해당 데이터는 폐기될 것입니다.
		 *
		 * SYN-ACK를 재전송한 후 타이머를 재설정하는데, 이는 복구 중의 빠른 재전송 아이디어와 유사합니다.
		 */

		// 속도 제한을 받지 않는 경우
		if (tcp_oow_rate_limited(sock_net(sk), skb, LINUX_MIB_TCPACKSKIPPEDSYNRECV, &tcp_rsk(req)->last_oow_ack_time) == false)
		{
			// SYN-ACK를 재응답 합니다.
			if (inet_rtx_syn_ack(sk, req) == 0)
			{
				// 전송에 실패한 경우 타이머를 재설정합니다.
				unsigned long expires = jiffies;

				expires += min(TCP_TIMEOUT_INIT << req->num_timeout, TCP_RTO_MAX);
				if (!fastopen)
					mod_timer_pending(&req->rsk_timer, expires);
				else
					req->rsk_timer.expires = expires;
			}
		}

		// 속도 제한이 걸린 경우는 아무 것도 하지 않습니다.
		return NULL;
	}

	/*
	 * RFC 793에 설명된 대로 SYN-RECEIVED 상태에서 세그먼트가 도착했을 때의 처리를 재현합니다.
	 * 그러나 SYN 패킷이 서로 교차하는 상황에서는 이 처리가 제대로 되지 않습니다.
	 *
	 * SYN 교차가 불가능할 것처럼 보이지만(우리 쪽에는 SYN_SENT 소켓(연결(connect())에서)이 있어야하므로),
	 * 실제로는 악의적인 제 3자가 두 엔드포인트에 동일한 시퀀스 번호를 가진 SYN 패킷을 보낼 수 있습니다.
	 * 이런 경우를 방어하기 위해 ACK를 검증하고, 유효하지 않은 ACK는 연결을 reset 합니다.
	 *
	 * 이 방법이 완전한 방어책인지 확신하기 위해, '악의적인 SYN 교차' 상황에서 ACK 검증이 어떻게 여전히 통과할 수 있는지를 살펴봅니다.
	 *
	 * 악의적인 송신자가 A와 B에게 동일한 SYN(따라서 동일한 순서 번호)를 보냅니다:
	 * A: gets SYN, seq=7
	 * B: gets SYN, seq=7
	 * 운 좋게도, A와 B 모두 동일한 초기 전송 시퀀스 번호 7을 선택합니다 :-)
	 *
	 * A: sends SYN|ACK, seq=7, ack_seq=8
	 * B: sends SYN|ACK, seq=7, ack_seq=8
	 *
	 * 양쪽 모두 SYN|ACK 패킷을 전송하고 서로의 SYN|ACK를 수신하여 ACK 검증을 통과하게 됩니다.
	 * A가 SYN|ACK 패킷을 수신하고, ACK 검증과 시퀀스 검증을 모두 통과합니다. SYN 플래그가 없으므로 이를 순수한 ACK로 처리합니다.
	 *
	 * icsk->icsk_accept_queue.rskq_defer_accept 가 설정된 경우, 이 순수한 ACK를 조용히 무시합니다.
	 * 그렇지 않으면, 연결을 설정합니다.
	 * 양쪽 엔드포인트(리스닝 소켓)가 새로운 수신 연결을 받아들이고 서로 통신을 시도합니다. 8-)
	 *
	 * Note: 이 상황은 매우 드물고 해가 없으며, 실제로 발생할 가능성은 매우 낮습니다.
	 * 내일 다른 행성에서 지적 생명체를 발견할 가능성과 거의 같습니다.
	 *
	 * 하지만 일반적으로, 우리는 여기와 tcp_rcv_state_process() 에서 SYN-ACK에 대한 ACK를 받아들여야 합니다(RFC가 잘못되었습니다!).
	 * tcp_rcv_state_process() 에서 그렇게 하지 않기 때문에, 우리도 그렇게 하지 않습니다.
	 *
	 * 이 상황은 일반적인 상황이며, 프로토콜을 위반하지 않고는 최적화가 불가능합니다.
	 * 소켓을 생성하기 전에 모든 검사를 수행해야 합니다.
	 */

	/*
	 * RFC793 page 36: "If the connection is in any non-synchronized state and the incoming segment acknowledges something not yet sent (the segment carries an unacceptable ACK) a reset is sent."
	 * "연결이 동기화되지 않은 상태이고, 수신된 세그먼트가 아직 전송되지 않은 것을 확인(ACK)하는 경우
	 * (세그먼트가 유효하지 않은 ACK 를 포함하면) RST 패킷이 전송됩니다."
	 *
	 * 유효하지 않은 ACK가 수신되면 리스닝 소켓에서 RST 패킷을 전송합니다.
	 * Fast Open 기능이 활성화된 소켓의 경우, ACK 유효성 검사는 다른 곳에서 수행되며,
	 * 사용자 데이터가 전송되었을 수 있으므로 ACK 유효성 검사는 req가 아닌 자식 소켓에 대해 직접 확인됩니다.
	 */
	if ((flg & TCP_FLAG_ACK)										// ACK 를 포함하고,
		&& fastopen == false										// fastopen 소켓이 아니며,
		&& (TCP_SKB_CB(skb)->ack_seq != tcp_rsk(req)->snt_isn + 1)) // ACK 시퀀스 넘버가 예상된 시퀀스 넘버와 다른 경우
	{
		// RST 패킷을 전송합니다.
		return sk;
	}

	/*
	 * 또한, ACK 확장인 rcv_tsecr 을 확인하는 것도 나쁘지 않은 아이디어입니다.
	 * 너무 이르거나 너무 늦은 값은 동기화 되지 않은 상태에서 리셋이 발생해야 합니다.
	 */

	// RFC793: "먼저 시퀀스 번호를 확인합니다."
	if (paws_reject == true
		|| tcp_in_window(								//
			   TCP_SKB_CB(skb)->seq,					//
			   TCP_SKB_CB(skb)->end_seq,				//
			   tcp_rsk(req)->rcv_nxt,					//
			   tcp_rsk(req)->rcv_nxt + req->rsk_rcv_wnd //
			   )
			   == false)
	{
		/* Out of window: send ACK and drop. */
		if ((flg & TCP_FLAG_RST) == 0																							   // RST 가 아니며
			&& tcp_oow_rate_limited(sock_net(sk), skb, LINUX_MIB_TCPACKSKIPPEDSYNRECV, &tcp_rsk(req)->last_oow_ack_time) == false) // 속도 제한이 걸리지 않은 경우
		{
			req->rsk_ops->send_ack(sk, skb, req);
		}
		if (paws_reject)
			__NET_INC_STATS(sock_net(sk), LINUX_MIB_PAWSESTABREJECTED);
		return NULL;
	}

	// 시퀀스가 올바르며, PAWS가 OK입니다.
	if (tmp_opt.saw_tstamp && !after(TCP_SKB_CB(skb)->seq, tcp_rsk(req)->rcv_nxt))
		req->ts_recent = tmp_opt.rcv_tsval;

	if (TCP_SKB_CB(skb)->seq == tcp_rsk(req)->rcv_isn)
	{
		// 시퀀스가 초기 수신 ISN과 동일하면 SYN 초기 단계이므로 여기서는 SYN 플래그를 제거합니다.
		// 이것은 tcp_rsk(req)->rcv_isn + 1에서 시작하는 윈도우 밖에 있습니다.
		flg &= ~TCP_FLAG_SYN;
	}

	// RFC793: "두 번째로 RST 비트를 확인하고", "네 번째로 SYN 비트를 확인합니다."
	if (flg & (TCP_FLAG_RST | TCP_FLAG_SYN))
	{
		__TCP_INC_STATS(sock_net(sk), TCP_MIB_ATTEMPTFAILS);
		goto embryonic_reset;
	}

	/*
	 * 위에서 ACK 시퀀스가 확인되었으므로 ACK가 설정되어 있는지 확인합니다.
	 * ACK가 설정되어 있지 않으면 패킷을 조용히 삭제합니다.
	 *
	 * TCP Fast Open 기능을 사용하게 되면, SYN 패킷 이후에 데이터를 전송할 수 있습니다.
	 * 이 경우, 현재 ACK 플래그를 확인하는 검사를 제거해야 할 수도 있습니다.
	 */
	if ((flg & TCP_FLAG_ACK) == 0)
		return NULL;

	// For Fast Open no more processing is needed (sk is the child socket).
	// 번역: Fast Open의 경우 더 이상 처리가 필요하지 않습니다(sk는 자식 소켓입니다).
	if (fastopen)
		return sk;

	/* While TCP_DEFER_ACCEPT is active, drop bare ACK. */
	if (req->num_timeout < inet_csk(sk)->icsk_accept_queue.rskq_defer_accept && TCP_SKB_CB(skb)->end_seq == tcp_rsk(req)->rcv_isn + 1)
	{
		inet_rsk(req)->acked = 1;
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPDEFERACCEPTDROP);
		return NULL;
	}

	// 좋아요. ACK가 유효하므로 큰 소켓을 만들고 이 세그먼트를 전달합니다.
	// 모든 테스트를 반복합니다.
	// 이 세그먼트는 소켓을 ESTABLISHED 상태로 이동해야 합니다.
	// 소켓이 생성된 후 삭제되면 문제가 발생합니다.
	// child = inet_csk(sk)->icsk_af_ops->syn_recv_sock(sk, skb, req, NULL, req, &own_req);
	struct sock* child = tcp_v4_syn_recv_sock(sk, skb, req, NULL, req, &own_req);
	if (child == NULL)
		goto listen_overflow;

	if (own_req && rsk_drop_req(req))
	{
		reqsk_queue_removed(&inet_csk(req->rsk_listener)->icsk_accept_queue, req);
		inet_csk_reqsk_queue_drop_and_put(req->rsk_listener, req);
		return child;
	}

	sock_rps_save_rxhash(child, skb);
	tcp_synack_rtt_meas(child, req);

	// 삽입에 실패했다면 뺏긴 것이다.
	*req_stolen = (own_req == false) //
					  ? true
					  : false;
	return inet_csk_complete_hashdance(sk, child, req, own_req);

// 위에서 처리되지 않은 경우, 여기부터는 실패 케이스에 해당한다.
listen_overflow:
	if (sk != req->rsk_listener)
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMIGRATEREQFAILURE);

	if (!sock_net(sk)->ipv4.sysctl_tcp_abort_on_overflow)
	{
		inet_rsk(req)->acked = 1;
		return NULL;
	}

embryonic_reset:
	if ((flg & TCP_FLAG_RST) == 0) // RST 플래그가 없는 경우
	{
		// 잘못된 SYN 패킷을 수신했습니다.
		// TFO 기능이 활성화된 경우, 불필요한 연결 reset 을 피하기 위해 정말 필요한지 확인하여 신중하게 처리합니다.
		// 이는 외부 공격으로 인해 정당한 연결이 reset 되는 것을 방지하기 위함입니다.
		req->rsk_ops->send_reset(sk, skb);
		// tcp_v4_send_reset(sk, skb);
	}
	else if (fastopen) // RST 플래그가 있고, fastopen 소켓이라면
	{
		// 유효한 RST 패킷을 수신했습니다. 연결 reset 을 수행합니다.
		reqsk_fastopen_remove(sk, req, true);
		tcp_reset(sk, skb);
	}
	if (fastopen == false)
	{
		bool unlinked = inet_csk_reqsk_queue_drop(sk, req);
		if (unlinked == true)
		{
			__NET_INC_STATS(sock_net(sk), LINUX_MIB_EMBRYONICRSTS);
		}

		// unlink 실패시 true, 성공시 false
		*req_stolen = (unlinked == false) ? true : false;
	}
	return NULL;
}
EXPORT_SYMBOL(tcp_check_req);

/// @brief
/// 	새 소켓이 활성화되어 있으면 세그먼트를 새 소켓에 대기열에 넣고, 그렇지 않으면 이를 단순화하고 새 소켓으로 계속합니다.
// 		대부분의 경우 child->sk_state가 TCP_SYN_RECV로 입력됩니다.
// 		그러나 __inet_lookup_established()가 실패한 후에 리스너 잠금이 획득되기 전에 다른 패킷으로 인해 동일한 연결이 생성되는 경합 조건으로 인해 다른 상태가 발생할 수 있습니다.
/// @param parent
/// @param child
/// @param skb
/// @return
int tcp_child_process(struct sock* parent, struct sock* child, struct sk_buff* skb) __releases(&((child)->sk_lock.slock))
{
	int ret = 0;
	int state = child->sk_state;

	/* record NAPI ID of child */
	sk_mark_napi_id(child, skb);

	tcp_segs_in(tcp_sk(child), skb);
	if (sock_owned_by_user(child) == false)
	{
		ret = tcp_rcv_state_process(child, skb);
		/* Wakeup parent, send SIGIO */
		if (state == TCP_SYN_RECV && child->sk_state != state)
			parent->sk_data_ready(parent);
	}
	else
	{
		// 유감스럽게도, 다시 발생할 수 있습니다.
		// 왜냐하면 우리는 메인 소켓 해시 테이블에서 조회하고, 리스닝 소켓의 잠금이 더 이상 보호하지 않기 때문입니다.
		__sk_add_backlog(child, skb);
	}

	bh_unlock_sock(child);
	sock_put(child);
	return ret;
}
EXPORT_SYMBOL(tcp_child_process);

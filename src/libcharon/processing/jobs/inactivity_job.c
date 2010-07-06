/*
 * Copyright (C) 2010 Martin Willi
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "inactivity_job.h"

#include <hydra.h>
#include <daemon.h>

typedef struct private_inactivity_job_t private_inactivity_job_t;

/**
 * Private data of an inactivity_job_t object.
 */
struct private_inactivity_job_t {

	/**
	 * Public inactivity_job_t interface.
	 */
	inactivity_job_t public;

	/**
	 * Reqid of CHILD_SA to check
	 */
	u_int32_t reqid;

	/**
	 * Inactivity timeout
	 */
	u_int32_t timeout;

	/**
	 * Close IKE_SA if last remaining CHILD inactive?
	 */
	bool close_ike;
};

METHOD(job_t, destroy, void,
	private_inactivity_job_t *this)
{
	free(this);
}

METHOD(job_t, execute, void,
	private_inactivity_job_t *this)
{
	ike_sa_t *ike_sa;
	bool rescheduled = FALSE;

	ike_sa = charon->ike_sa_manager->checkout_by_id(charon->ike_sa_manager,
													this->reqid, TRUE);
	if (ike_sa)
	{
		iterator_t *iterator;
		child_sa_t *child_sa;
		u_int32_t delete = 0;
		protocol_id_t proto = 0;
		int children = 0;
		status_t status = SUCCESS;

		iterator = ike_sa->create_child_sa_iterator(ike_sa);
		while (iterator->iterate(iterator, (void**)&child_sa))
		{
			if (child_sa->get_reqid(child_sa) == this->reqid)
			{
				time_t in, out, diff;

				child_sa->get_usestats(child_sa, TRUE, &in, NULL);
				child_sa->get_usestats(child_sa, FALSE, &out, NULL);

				diff = time_monotonic(NULL) - max(in, out);

				if (diff >= this->timeout)
				{
					delete = child_sa->get_spi(child_sa, TRUE);
					proto = child_sa->get_protocol(child_sa);
				}
				else
				{
					hydra->scheduler->schedule_job(hydra->scheduler,
							&this->public.job_interface, this->timeout - diff);
					rescheduled = TRUE;
				}
			}
			children++;
		}
		iterator->destroy(iterator);

		if (delete)
		{
			if (children == 1 && this->close_ike)
			{
				DBG1(DBG_JOB, "deleting IKE_SA after %d seconds "
					 "of CHILD_SA inactivity", this->timeout);
				status = ike_sa->delete(ike_sa);
			}
			else
			{
				DBG1(DBG_JOB, "deleting CHILD_SA after %d seconds "
					 "of inactivity", this->timeout);
				status = ike_sa->delete_child_sa(ike_sa, proto, delete);
			}
		}
		if (status == DESTROY_ME)
		{
			charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager,
														ike_sa);
		}
		else
		{
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		}
	}
	if (!rescheduled)
	{
		destroy(this);
	}
}

/**
 * See header
 */
inactivity_job_t *inactivity_job_create(u_int32_t reqid, u_int32_t timeout,
										bool close_ike)
{
	private_inactivity_job_t *this;

	INIT(this,
		.public = {
				.job_interface = {
				.execute = _execute,
				.destroy = _destroy,
			},
		},
		.reqid = reqid,
		.timeout = timeout,
		.close_ike = close_ike,
	);

	return &this->public;
}


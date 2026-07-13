package grants

// CancelForClient atomically cancels a pending grant owned by client.
func (s *Store) CancelForClient(id, client string) (Grant, error) {
	return s.closeForClient(id, client, StatusPending, StatusCanceled)
}

// RevokeForClient atomically revokes an active grant owned by client.
func (s *Store) RevokeForClient(id, client string) (Grant, error) {
	return s.closeForClient(id, client, StatusActive, StatusRevoked)
}

func (s *Store) closeForClient(id, client string, required, next Status) (Grant, error) {
	var out Grant
	err := s.update(func(data *fileData) error {
		index, grant, err := findGrant(data.Grants, id)
		if err != nil || grant.Client != client {
			return ErrNotFound
		}
		if grant.Status != required {
			if required == StatusPending {
				return ErrNotPending
			}
			return ErrNotActive
		}
		grant.Status = next
		grant.DecidedAt = s.opts.Now().UTC()
		grant.DecidedBy = client
		clearNotificationClaim(&grant)
		data.Grants[index], out = grant, grant
		return nil
	})
	return out, err
}

package memory

import "github.com/Akhilmadineni/clixor-backend/internal/compliance"

func (s *Store) Compliance() compliance.Repository { return s.compliance }

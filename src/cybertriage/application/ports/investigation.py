from typing import Protocol

from cybertriage.domain.investigation import (
    AuthenticationSearchRequest,
    AuthenticationSearchResult,
)


class AuthenticationEventSearcher(Protocol):
    def search(
        self,
        request: AuthenticationSearchRequest,
    ) -> AuthenticationSearchResult:
        """
        Search Windows Security logons for the requested account.

        Return matching events with source identifiers and coverage.
        Indicate when additional matching results were omitted.
        Raise InvestigationSearchError if the search cannot be
        completed reliably, including partial backend failures.
        """
        ...
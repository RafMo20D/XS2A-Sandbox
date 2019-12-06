package de.adorsys.psd2.sandbox.tpp.rest.server.service;

import de.adorsys.ledgers.middleware.api.domain.account.AccountDetailsTO;
import de.adorsys.ledgers.middleware.api.domain.payment.SinglePaymentTO;
import de.adorsys.ledgers.middleware.api.domain.um.AccessTypeTO;
import de.adorsys.ledgers.middleware.api.domain.um.AccountAccessTO;
import de.adorsys.ledgers.middleware.api.domain.um.UserTO;
import de.adorsys.ledgers.middleware.client.rest.UserMgmtRestClient;
import de.adorsys.psd2.sandbox.tpp.rest.server.model.AccountBalance;
import de.adorsys.psd2.sandbox.tpp.rest.server.model.DataPayload;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.IBANValidator;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.http.ResponseEntity;

import java.util.*;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class TestsDataGenerationServiceTest {
    private static final String TPP_ID = "DE_12345678";
    private static final String USER_IBAN = "DE89000000115555555555";
    private static final String USER_ID = "QWERTY";
    private static final Currency CURRENCY = Currency.getInstance("EUR");

    @InjectMocks
    private IbanGenerationService generationService;
    @Mock
    private UserMgmtRestClient userMgmtRestClient;

    @Test
    public void generateIban() {
        when(userMgmtRestClient.getUser()).thenReturn(ResponseEntity.ok(new UserTO(null, null, null, null, null, Collections.EMPTY_LIST, null, TPP_ID)));
        String iban = generationService.generateNextIban();
        boolean isIbanValid = IBANValidator.getInstance().isValid(iban);
        assertTrue(isIbanValid);
    }

    @Test
    public void generateNispIban() {
        when(userMgmtRestClient.getUser()).thenReturn(ResponseEntity.ok(new UserTO(null, null, null, null, null, getAccountAccess(), null, TPP_ID)));
        String s = generationService.generateIbanForNisp(getPayload(), "00");
        assertTrue(StringUtils.isNotBlank(s));
    }

    private DataPayload getPayload() {
        List<UserTO> users = Collections.singletonList(new UserTO("login", "email", "pin"));
        List<AccountDetailsTO> accounts = Collections.singletonList(new AccountDetailsTO());
        List<AccountBalance> balances = Collections.singletonList(new AccountBalance());
        List<SinglePaymentTO> payments = Collections.singletonList(new SinglePaymentTO());
        return new DataPayload(users, accounts, balances, payments, false, TPP_ID, new HashMap<>());
    }

    private List<AccountAccessTO> getAccountAccess() {
        AccountAccessTO accountAccess = new AccountAccessTO();
        accountAccess.setCurrency(CURRENCY);
        accountAccess.setAccessType(AccessTypeTO.OWNER);
        accountAccess.setScaWeight(50);
        accountAccess.setIban(USER_IBAN);
        accountAccess.setId(USER_ID);
        return Collections.singletonList(accountAccess);
    }
}

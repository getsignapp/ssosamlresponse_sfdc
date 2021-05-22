//This class provides logic for inbound just-in-time provisioning of single sign-on users in your Salesforce organization.
global class AutocreatedRegHandler1621622785596 implements Auth.SamlJitHandler {
    private class JitException extends Exception{}
    
    private string pName = 'Customer Community Plus User';
    private string rName = 'CEO';
    
    private String handleAccount(boolean create, User u, Map<String, String> attributes) {
        Account a;
        boolean newAccount = false;
        if(create) {
            a = new Account();
            newAccount = true;
        } else {
            List<User> ut = [Select Id,ContactId,Contact.AccountId from User where Id =: u.Id];
            if(!ut.isEmpty()) {
            String account = attributes.get('User.Account');
                a = [SELECT Id FROM Account WHERE Id =: ut[0].Contact.AccountId];
            } else {
                a = new Account();
                newAccount = true;
            }
        }
        
        if(attributes.containsKey('Account.Name')) {
            a.Name = attributes.get('Account.Name');
        }
        if(attributes.containsKey('Account.AccountNumber')) {
            a.AccountNumber = attributes.get('Account.AccountNumber');
        }
        if(attributes.containsKey('Account.Owner')) {
            a.OwnerId = attributes.get('Account.Owner');
        }
        if(attributes.containsKey('Account.BillingStreet')) {
            a.BillingStreet = attributes.get('Account.BillingStreet');
        }
        if(attributes.containsKey('Account.BillingCity')) {
            a.BillingCity = attributes.get('Account.BillingCity');
        }
        if(attributes.containsKey('Account.BillingState')) {
            a.BillingState = attributes.get('Account.BillingState');
        }
        if(attributes.containsKey('Account.BillingCountry')) {
            a.BillingCountry = attributes.get('Account.BillingCountry');
        }
        if(attributes.containsKey('Account.BillingPostalCode')) {
            a.BillingPostalCode = attributes.get('Account.BillingPostalCode');
        }
        if(attributes.containsKey('Account.AnnualRevenue')) {
            a.AnnualRevenue = Integer.valueOf(attributes.get('Account.AnnualRevenue'));
        }
        if(attributes.containsKey('Account.Description')) {
            a.Description = attributes.get('Account.Description');
        }
        if(attributes.containsKey('Account.Fax')) {
            a.Fax = attributes.get('Account.Fax');
        }
        if(attributes.containsKey('Account.NumberOfEmployees')) {
            a.NumberOfEmployees = Integer.valueOf(attributes.get('Account.NumberOfEmployees'));
        }
        if(attributes.containsKey('Account.Phone')) {
            a.Phone = attributes.get('Account.Phone');
        }
        if(attributes.containsKey('Account.ShippingStreet')) {
            a.ShippingStreet = attributes.get('Account.ShippingStreet');
        }
        if(attributes.containsKey('Account.ShippingCity')) {
            a.ShippingCity = attributes.get('Account.ShippingCity');
        }
        if(attributes.containsKey('Account.ShippingState')) {
            a.ShippingState = attributes.get('Account.ShippingState');
        }
        if(attributes.containsKey('Account.ShippingCountry')) {
            a.ShippingCountry = attributes.get('Account.ShippingCountry');
        }
        if(attributes.containsKey('Account.ShippingPostalCode')) {
            a.ShippingPostalCode = attributes.get('Account.ShippingPostalCode');
        }
        if(attributes.containsKey('Account.Sic')) {
            a.Sic = attributes.get('Account.Sic');
        }
        if(attributes.containsKey('Account.TickerSymbol')) {
            a.TickerSymbol = attributes.get('Account.TickerSymbol');
        }
        if(attributes.containsKey('Account.Website')) {
            a.Website = attributes.get('Account.Website');
        }
        if(attributes.containsKey('Account.Industry')) {
            a.Industry = attributes.get('Account.Industry');
        }
        if(attributes.containsKey('Account.Ownership')) {
            a.Ownership = attributes.get('Account.Ownership');
        }
        if(attributes.containsKey('Account.Rating')) {
            a.Rating = attributes.get('Account.Rating');
        }
        if(newAccount) {
            insert(a);
        } else {
            update(a);
        }
        return a.Id;
    }
    
    private void handleContact(boolean create, String accountId, User u, Map<String, String> attributes) {
        Contact c;
        boolean newContact = false;
        if(create) {
            c = new Contact();
            newContact = true;
        } else {
            List<User> ut = [Select Id,ContactId,Contact.AccountId from User where Id =: u.Id];
            if(!ut.isEmpty()) {
                c = [SELECT Id, AccountId FROM Contact WHERE Id =: ut[0].ContactId];
            } else {
                c = new Contact();
                newContact = true;
            }
        }
        if(!newContact && c.AccountId != accountId) {
            throw new JitException('Mismatched account: ' + c.AccountId + ', ' + accountId);
        }

        if(attributes.containsKey('Contact.Email')) {
            c.Email = attributes.get('Contact.Email');
        }
        if(attributes.containsKey('Contact.FirstName')) {
            c.FirstName = attributes.get('Contact.FirstName');
        }
        if(attributes.containsKey('Contact.LastName')) {
            c.LastName = attributes.get('Contact.LastName');
        }
        if(attributes.containsKey('Contact.Phone')) {
            c.Phone = attributes.get('Contact.Phone');
        }
        if(attributes.containsKey('Contact.MailingStreet')) {
            c.MailingStreet = attributes.get('Contact.MailingStreet');
        }
        if(attributes.containsKey('Contact.MailingCity')) {
            c.MailingCity = attributes.get('Contact.MailingCity');
        }
        if(attributes.containsKey('Contact.MailingState')) {
            c.MailingState = attributes.get('Contact.MailingState');
        }
        if(attributes.containsKey('Contact.MailingCountry')) {
            c.MailingCountry = attributes.get('Contact.MailingCountry');
        }
        if(attributes.containsKey('Contact.MailingPostalCode')) {
            c.MailingPostalCode = attributes.get('Contact.MailingPostalCode');
        }
        if(attributes.containsKey('Contact.OtherStreet')) {
            c.OtherStreet = attributes.get('Contact.OtherStreet');
        }
        if(attributes.containsKey('Contact.OtherCity')) {
            c.OtherCity = attributes.get('Contact.OtherCity');
        }
        if(attributes.containsKey('Contact.OtherState')) {
            c.OtherState = attributes.get('Contact.OtherState');
        }
        if(attributes.containsKey('Contact.OtherCountry')) {
            c.OtherCountry = attributes.get('Contact.OtherCountry');
        }
        if(attributes.containsKey('Contact.OtherPostalCode')) {
            c.OtherPostalCode = attributes.get('Contact.OtherPostalCode');
        }
        if(attributes.containsKey('Contact.AssistantPhone')) {
            c.AssistantPhone = attributes.get('Contact.AssistantPhone');
        }
        if(attributes.containsKey('Contact.Department')) {
            c.Department = attributes.get('Contact.Department');
        }
        if(attributes.containsKey('Contact.Description')) {
            c.Description = attributes.get('Contact.Description');
        }
        if(attributes.containsKey('Contact.Fax')) {
            c.Fax = attributes.get('Contact.Fax');
        }
        if(attributes.containsKey('Contact.HomePhone')) {
            c.HomePhone = attributes.get('Contact.HomePhone');
        }
        if(attributes.containsKey('Contact.MobilePhone')) {
            c.MobilePhone = attributes.get('Contact.MobilePhone');
        }
        if(attributes.containsKey('Contact.OtherPhone')) {
            c.OtherPhone = attributes.get('Contact.OtherPhone');
        }
        if(attributes.containsKey('Contact.Title')) {
            c.Title = attributes.get('Contact.Title');
        }
        if(attributes.containsKey('Contact.Salutation')) {
            c.Salutation = attributes.get('Contact.Salutation');
        }
        if(attributes.containsKey('Contact.LeadSource')) {
            c.LeadSource = attributes.get('Contact.LeadSource');
        }
        if(attributes.containsKey('Contact.DoNotCall')) {
            String DoNotCallVal = attributes.get('Contact.DoNotCall');
            c.DoNotCall = '1'.equals(DoNotCallVal) || Boolean.valueOf(DoNotCallVal);
        }
        if(attributes.containsKey('Contact.HasOptedOutOfEmail')) {
            String HasOptedOutOfEmailVal = attributes.get('Contact.HasOptedOutOfEmail');
            c.HasOptedOutOfEmail = '1'.equals(HasOptedOutOfEmailVal) || Boolean.valueOf(HasOptedOutOfEmailVal);
        }
        if(attributes.containsKey('Contact.HasOptedOutOfFax')) {
            String HasOptedOutOfFaxVal = attributes.get('Contact.HasOptedOutOfFax');
            c.HasOptedOutOfFax = '1'.equals(HasOptedOutOfFaxVal) || Boolean.valueOf(HasOptedOutOfFaxVal);
        }
        if(attributes.containsKey('Contact.Owner')) {
            c.OwnerId = attributes.get('Contact.Owner');
        }
        if(attributes.containsKey('Contact.AssistantName')) {
            c.AssistantName = attributes.get('Contact.AssistantName');
        }
        if(attributes.containsKey('Contact.Birthdate')) {
            c.Birthdate = Date.valueOf(attributes.get('Contact.Birthdate'));
        }
        if(newContact) {
            c.AccountId = accountId;
            insert(c);
            u.ContactId = c.Id;
        } else {
            update(c);
        }
    }
    
    private void handleUser(boolean create, User u, Map<String, String> attributes,
        String federationIdentifier, boolean isStandard) {
                
        if(attributes.containsKey('Contact.Phone')) {
            u.Phone = attributes.get('Contact.Phone');
        }
        if(attributes.containsKey('Contact.Email')) {
            u.Email = attributes.get('Contact.Email');
        }
        if(attributes.containsKey('Contact.FirstName')) {
            u.FirstName = attributes.get('Contact.FirstName');
        }
        if(attributes.containsKey('Contact.LastName')) {
            u.LastName = attributes.get('Contact.LastName');
        }
        if(attributes.containsKey('Contact.Title')) {
            u.Title = attributes.get('Contact.Title');
        }
        if(attributes.containsKey('Account.CompanyName')) {
            u.CompanyName = attributes.get('Account.CompanyName');
        }
        if(attributes.containsKey('Contact.MailingStreet')) {
            u.Street = attributes.get('Contact.MailingStreet');
        }
        if(attributes.containsKey('Contact.MailingState')) {
            u.State = attributes.get('Contact.MailingState');
        }
        if(attributes.containsKey('Contact.MailingCity')) {
            u.City = attributes.get('Contact.MailingCity');
        }
        if(attributes.containsKey('Contact.MailingPostalCode')) {
            u.PostalCode = attributes.get('Contact.MailingPostalCode');
        }
        if(attributes.containsKey('Contact.MailingCountry')) {
            u.Country = attributes.get('Contact.MailingCountry');
        }
        if(attributes.containsKey('Contact.MobilePhone')) {
            u.MobilePhone = attributes.get('Contact.MobilePhone');
        }
        if(attributes.containsKey('Contact.Fax')) {
            u.Fax = attributes.get('Contact.Fax');
        }
        
        String uid = UserInfo.getUserId();
        User currentUser = 
            [SELECT LocaleSidKey, LanguageLocaleKey, TimeZoneSidKey, EmailEncodingKey FROM User WHERE Id=:uid];
        String unqId = String.valueOf(Datetime.now().getTime());
        
        if(create){
            u.FederationIdentifier = federationIdentifier;
            u.Username = unqId + '_' + u.Email;
            //u.IsActive = true;
            u.ReceivesAdminInfoEmails = false;
            u.ReceivesInfoEmails = false;
            u.LocaleSidKey = currentUser.LocaleSidKey;
            u.LanguageLocaleKey = currentUser.LanguageLocaleKey;
            u.TimeZoneSidKey = currentUser.TimeZoneSidKey;
            u.EmailEncodingKey = currentUser.EmailEncodingKey;
            
            String alias = '';
            if(u.FirstName == null) {
                alias = u.LastName;
            } else {
                alias = u.FirstName.charAt(0) + u.LastName;
            }
            if(alias.length() > 5) {
                alias = alias.substring(0, 5);
            }
            u.Alias = alias;
            u.CommunityNickname = alias;
            
            Profile p = [SELECT Id FROM Profile WHERE Name =: pName];
            u.ProfileId = p.Id;
            
            UserRole r = [SELECT Id FROM UserRole WHERE Name =: rName];
            //u.UserRoleId = r.Id;
        }
        
        /*
         * isActive, ProfileId, RoleId, ForecastEnabled should not be updated when user is updated
        */
        
        if(!create) {
            update(u);
        }
    }

    private void handleJit(boolean create, User u, Id samlSsoProviderId, Id communityId, Id portalId,
        String federationIdentifier, Map<String, String> attributes, String assertion) {
        
        system.debug('>>create>>' + create);
        if(create){
            //TODO callout to get any data here and then only do any DML to avoid error
        }
        
        if(communityId != null || portalId != null) {
            String account = handleAccount(create, u, attributes);
            handleContact(create, account, u, attributes);
            handleUser(create, u, attributes, federationIdentifier, false);
        } else {
            //handleUser(create, u, attributes, federationIdentifier, true);
        }
    }

    global User createUser(Id samlSsoProviderId, Id communityId, Id portalId,
        String federationIdentifier, Map<String, String> attributes, String assertion) {
        
        system.debug('>>CR>>' + JSON.serialize(attributes));
        system.debug('>>CR>>' + samlSsoProviderId);
        system.debug('>>CR>>' + communityId);
        system.debug('>>CR>>' + portalId);
        
        User u = new User();
        handleJit(true, u, samlSsoProviderId, communityId, portalId,
            federationIdentifier, attributes, assertion);
        return u;
    }

    global void updateUser(Id userId, Id samlSsoProviderId, Id communityId, Id portalId,
        String federationIdentifier, Map<String, String> attributes, String assertion) {
        
        system.debug('>>UP>>' + JSON.serialize(attributes));
        system.debug('>>UR>>' + userId);
        
        User u = [SELECT Id, FirstName, ContactId FROM User WHERE Id=:userId];
        handleJit(false, u, samlSsoProviderId, communityId, portalId,
            federationIdentifier, attributes, assertion);
    }
}
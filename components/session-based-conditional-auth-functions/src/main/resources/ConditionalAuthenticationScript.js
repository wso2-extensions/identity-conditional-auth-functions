function onInitialRequest(context) {
    executeStep({
        id: '1',
        on: {
            success: function (context) {
                var sessionAttributeMap = {};
                sessionAttributeMap["sessionLimit"] = "2";
                var isAllowed = isWithinSessionLimit(context, sessionAttributeMap);
                Log.info("Within Session Limit  :" + isAllowed)
                if (isAllowed) {
                    executeStep({id: '2'});
                }
                else {
                    executeStep({id: '3'});
                    executeStep({id: '2'});
                }
            }
        }
    });
}

unit uVvIdHttpServer;

interface

uses IdHTTPServer, IdCustomHTTPServer, IdContext, System.Classes, IdGlobal, IdURI, IdExceptionCore,
     System.SysUtils, IdTCPConnection, IdIOHandlerSocket, IdIOHandler, IdStackConsts,
     IdResourceStringsProtocols, IdResourceStringsCore, IdGlobalProtocols, IdStack;

type
  TIdHttpServerExt = class(TIdHTTPServer)
  protected
    function DoExecute(AContext:TIdContext): Boolean; override;
  end;


  TIdHttpRequestInfoExt = class(TIdHTTPRequestInfo)
  protected
    //FPostStream: TStream;
  end;

  TIdHttpResponseInfoExt = class(TIdHTTPResponseInfo)
  private
    FHeaderExt: TStringList;
  protected
    procedure SetHeaders; override;
  public
    constructor Create(AServer: TIdCustomHTTPServer;
      ARequestInfo: TIdHTTPRequestInfo; AConnection: TIdTCPConnection);
    destructor Destroy; override;

    property HeaderExt: TStringList read FHeaderExt;
  end;


implementation

const
  ContentTypeFormUrlencoded = 'application/x-www-form-urlencoded'; {Do not Localize}

function DecodeHTTPCommand(const ACmd: string): THTTPCommandType;
var
  I: Integer;
begin
  Result := hcUnknown;
  for I := Low(HTTPRequestStrings) to High(HTTPRequestStrings) do begin
    if TextIsSame(ACmd, HTTPRequestStrings[i]) then begin
      Result := THTTPCommandType(i);
      Exit;
    end;
  end;    // for
end;


function InternalReadLn(AIOHandler: TIdIOHandler): String;
begin
  Result := AIOHandler.ReadLn;
  if AIOHandler.ReadLnTimedout then begin
    raise EIdReadTimeout.Create(RSReadTimeout);
  end;
end;

constructor TIdHTTPResponseInfoExt.Create(AServer: TIdCustomHTTPServer;
  ARequestInfo: TIdHTTPRequestInfo; AConnection: TIdTCPConnection);
begin
  inherited Create(AServer, ARequestInfo, AConnection);
  FHeaderExt := TStringList.Create;
  FHeaderExt.NameValueSeparator := ':';
end;

destructor TIdHTTPResponseInfoExt.Destroy;
begin
  FreeAndNil(FHeaderExt);
  inherited Destroy;
end;


procedure TIdHTTPResponseInfoExt.SetHeaders;
begin
  inherited SetHeaders;
  FRawHeaders.AddStrings(FHeaderExt);
end;

{ TIdHttpServerExt }

function TIdHttpServerExt.DoExecute(AContext: TIdContext): Boolean;
var
  LRequestInfo: TIdHTTPRequestInfoExt;
  LResponseInfo: TIdHTTPResponseInfoExt;

  procedure ReadCookiesFromRequestHeader;
  var
    LRawCookies: TStringList;
  begin
    LRawCookies := TStringList.Create;
    try
      LRequestInfo.RawHeaders.Extract('Cookie', LRawCookies);    {Do not Localize}
      LRequestInfo.Cookies.AddClientCookies(LRawCookies);
    finally
      FreeAndNil(LRawCookies);
    end;
  end;

  function GetRemoteIP(ASocket: TIdIOHandlerSocket): String;
  begin
    Result := '';
    if ASocket <> nil then begin
      if ASocket.Binding <> nil then begin
        Result := ASocket.Binding.PeerIP;
      end;
    end;
  end;

  function HeadersCanContinue: Boolean;
  var
    LResponseNo: Integer;
    LResponseText, LContentText, S: String;
  begin
    // let the user decide if the request headers are acceptable
    Result := DoHeadersAvailable(AContext, LRequestInfo.URI, LRequestInfo.RawHeaders);
    if not Result then begin
      DoHeadersBlocked(AContext, LRequestInfo.RawHeaders, LResponseNo, LResponseText, LContentText);
      LResponseInfo.ResponseNo := LResponseNo;
      if Length(LResponseText) > 0 then begin
        LResponseInfo.ResponseText := LResponseText;
      end;
      LResponseInfo.ContentText := LContentText;
      LResponseInfo.CloseConnection := True;
      LResponseInfo.WriteHeader;
      if Length(LContentText) > 0 then begin
        LResponseInfo.WriteContent;
      end;
      Exit;
    end;

    // check for HTTP v1.1 'Host' and 'Expect' headers...

    if not LRequestInfo.IsVersionAtLeast(1, 1) then begin
      Exit;
    end;

    // MUST report a 400 (Bad Request) error if an HTTP/1.1
    // request does not include a 'Host' header
    S := LRequestInfo.RawHeaders.Values['Host'];
    if Length(S) = 0 then begin
      LResponseInfo.ResponseNo := 400;
      LResponseInfo.CloseConnection := True;
      LResponseInfo.WriteHeader;
      Exit;
    end;

    // if the client has already sent some or all of the request
    // body then don't bother checking for a v1.1 'Expect' header
    if not AContext.Connection.IOHandler.InputBufferIsEmpty then begin
      Exit;
    end;

    S := LRequestInfo.RawHeaders.Values['Expect'];
    if Length(S) = 0 then begin
      Exit;
    end;

    // check if the client expectations can be satisfied...
    Result := DoHeaderExpectations(AContext, S);
    if not Result then begin
      LResponseInfo.ResponseNo := 417;
      LResponseInfo.CloseConnection := True;
      LResponseInfo.WriteHeader;
      Exit;
    end;

    if Pos('100-continue', LowerCase(S)) > 0 then begin  {Do not Localize}
      // the client requested a '100-continue' expectation so send
      // a '100 Continue' reply now before the request body can be read
      AContext.Connection.IOHandler.WriteLn(LRequestInfo.Version + ' 100 ' + RSHTTPContinue + EOL);    {Do not Localize}
    end;
  end;

  function PreparePostStream: Boolean;
  var
    I, Size: Integer;
    S: String;
    LIOHandler: TIdIOHandler;
  begin
    Result := False;
    LIOHandler := AContext.Connection.IOHandler;

    // RLebeau 1/6/2009: don't create the PostStream unless there is
    // actually something to read. This should make it easier for the
    // request handler to know when to use the PostStream and when to
    // use the (Unparsed)Params instead...

    if (LRequestInfo.TransferEncoding <> '') and
      (not TextIsSame(LRequestInfo.TransferEncoding, 'identity')) then {do not localize}
    begin
      if IndyPos('chunked', LowerCase(LRequestInfo.TransferEncoding)) = 0 then begin {do not localize}
        LResponseInfo.ResponseNo := 400; // bad request
        LResponseInfo.CloseConnection := True;
        LResponseInfo.WriteHeader;
        Exit;
      end;
      CreatePostStream(AContext, LRequestInfo.RawHeaders, LRequestInfo.FPostStream);
      if LRequestInfo.FPostStream = nil then begin
        LRequestInfo.FPostStream := TMemoryStream.Create;
      end;
      LRequestInfo.PostStream.Position := 0;
      repeat
        S := InternalReadLn(LIOHandler);
        I := IndyPos(';', S); {do not localize}
        if I > 0 then begin
          S := Copy(S, 1, I - 1);
        end;
        Size := IndyStrToInt('$' + Trim(S), 0);      {do not localize}
        if Size = 0 then begin
          Break;
        end;
        LIOHandler.ReadStream(LRequestInfo.PostStream, Size);
        InternalReadLn(LIOHandler); // CRLF at end of chunk data
      until False;
      // skip trailer headers
      repeat until InternalReadLn(LIOHandler) = '';
      LRequestInfo.PostStream.Position := 0;
    end
    else if LRequestInfo.HasContentLength then
    begin
      CreatePostStream(AContext, LRequestInfo.RawHeaders, LRequestInfo.FPostStream);
      if LRequestInfo.FPostStream = nil then begin
        LRequestInfo.FPostStream := TMemoryStream.Create;
      end;
      LRequestInfo.PostStream.Position := 0;
      if LRequestInfo.ContentLength > 0 then begin
        LIOHandler.ReadStream(LRequestInfo.PostStream, LRequestInfo.ContentLength);
        LRequestInfo.PostStream.Position := 0;
      end;
    end
    // If HTTP Pipelining is used by the client, bytes may exist that belong to
    // the NEXT request!  We need to look at the CURRENT request and only check
    // for misreported body data if a body is actually expected.  GET and HEAD
    // requests do not have bodies...
    else if LRequestInfo.CommandType in [hcPOST, hcPUT] then
    begin
      if LIOHandler.InputBufferIsEmpty then begin
        LIOHandler.CheckForDataOnSource(1);
      end;
      if not LIOHandler.InputBufferIsEmpty then begin
        LResponseInfo.ResponseNo := 411; // length required
        LResponseInfo.CloseConnection := True;
        LResponseInfo.WriteHeader;
        Exit;
      end;
    end;
    Result := True;
  end;

var
  i: integer;
  s, LInputLine, LRawHTTPCommand, LCmd, LContentType, LAuthType: String;
  LURI: TIdURI;
  LContinueProcessing, LCloseConnection: Boolean;
  LConn: TIdTCPConnection;
  LEncoding: IIdTextEncoding;
begin
  LContinueProcessing := True;
  Result := False;
  LCloseConnection := not KeepAlive;
  try
    try
      LConn := AContext.Connection;
      repeat
        LInputLine := InternalReadLn(LConn.IOHandler);
        i := RPos(' ', LInputLine, -1);    {Do not Localize}
        if i = 0 then begin
          raise EIdHTTPErrorParsingCommand.Create(RSHTTPErrorParsingCommand);
        end;
        LRequestInfo := TIdHTTPRequestInfoExt.Create(Self);
        try
          LResponseInfo := TIdHTTPResponseInfoExt.Create(Self, LRequestInfo, LConn);
          try
            // SG 05.07.99
            // Set the ServerSoftware string to what it's supposed to be.    {Do not Localize}
            LResponseInfo.ServerSoftware := Trim(ServerSoftware);

            // S.G. 6/4/2004: Set the maximum number of lines that will be catured
            // S.G. 6/4/2004: to prevent a remote resource starvation DOS
            LConn.IOHandler.MaxCapturedLines := MaximumHeaderLineCount;

            // Retrieve the HTTP version
            LRawHTTPCommand := LInputLine;
            LRequestInfo.FVersion := Copy(LInputLine, i + 1, MaxInt);

            s := LRequestInfo.Version;
            Fetch(s, '/');  {Do not localize}
            LRequestInfo.FVersionMajor := IndyStrToInt(Fetch(s, '.'), -1);  {Do not Localize}
            LRequestInfo.FVersionMinor := IndyStrToInt(S, -1);

            SetLength(LInputLine, i - 1);

            // Retrieve the HTTP header
            LRequestInfo.RawHeaders.Clear;
            LConn.IOHandler.Capture(LRequestInfo.RawHeaders, '', False);    {Do not Localize}

            // in case the user needs to overwrite any values...
            LRequestInfo.ProcessHeaders;

            // HTTP 1.1 connections are keep-alive by default
            if not FKeepAlive then begin
              LResponseInfo.CloseConnection := True;
            end
            else if LRequestInfo.IsVersionAtLeast(1, 1) then begin
              LResponseInfo.CloseConnection := TextIsSame(LRequestInfo.Connection, 'close'); {Do not Localize}
            end else begin
              LResponseInfo.CloseConnection := not TextIsSame(LRequestInfo.Connection, 'keep-alive'); {Do not Localize}
            end;


            LCmd := UpperCase(Fetch(LInputLine, ' '));    {Do not Localize}

            // check for overrides when LCmd is 'POST'...
            if TextIsSame(LCmd, 'POST') then begin
              s := LRequestInfo.MethodOverride; // Google/GData
              if s = '' then begin

                s := LRequestInfo.RawHeaders.Values['X-HTTP-Method']; // Microsoft      {do not localize}
                if s = '' then begin
                  s := LRequestInfo.RawHeaders.Values['X-METHOD-OVERRIDE']; // IBM      {do not localize}
                end;
              end;
              if s <> '' then begin
                LCmd := UpperCase(s);
              end;
            end;

            LRequestInfo.FRawHTTPCommand := LRawHTTPCommand;
            LRequestInfo.FRemoteIP := GetRemoteIP(LConn.Socket);
            LRequestInfo.FCommand := LCmd;
            LRequestInfo.FCommandType := DecodeHTTPCommand(LCmd);

            // GET data - may exist with POSTs also
            LRequestInfo.QueryParams := LInputLine;
            LInputLine := Fetch(LRequestInfo.FQueryParams, '?');    {Do not Localize}

            // Host
            // the next line is done in TIdHTTPRequestInfo.ProcessHeaders()...
            // LRequestInfo.FHost := LRequestInfo.Headers.Values['host'];    {Do not Localize}

            LRequestInfo.FURI := LInputLine;

            // Parse the document input line
            if LInputLine = '*' then begin    {Do not Localize}
              LRequestInfo.FDocument := '*';    {Do not Localize}
            end else begin
              LURI := TIdURI.Create(LInputLine);
              try
                // SG 29/11/01: Per request of Doychin
                // Try to fill the "host" parameter
                LRequestInfo.FDocument := TIdURI.URLDecode(LURI.Path) + TIdURI.URLDecode(LURI.Document);
                if (Length(LURI.Host) > 0) and (Length(LRequestInfo.FHost) = 0) then begin
                  LRequestInfo.FHost := LURI.Host;
                end;
              finally
                FreeAndNil(LURI);
              end;
            end;

            // RLebeau 12/14/2005: provide the user with the headers and let the
            // user decide whether the response processing should continue...
            if not HeadersCanContinue then begin
              Break;
            end;

            // retreive the base ContentType with attributes omitted
            LContentType := ExtractHeaderItem(LRequestInfo.ContentType);

            // Grab Params so we can parse them
            // POSTed data - may exist with GETs also. With GETs, the action
            // params from the form element will be posted

            // Get data can exists with POSTs, but can POST data exist with GETs?
            // If only the first, the solution is easy. If both - need more
            // investigation.

            if not PreparePostStream then begin
              Break;
            end;

            if LRequestInfo.PostStream <> nil then begin
              if TextIsSame(LContentType, ContentTypeFormUrlencoded) then
              begin
                // decoding percent-encoded octets and applying the CharSet is handled by DecodeAndSetParams() further below...
                EnsureEncoding(LEncoding, enc8Bit);
                LRequestInfo.FormParams := ReadStringFromStream(LRequestInfo.PostStream, -1, LEncoding{$IFDEF STRING_IS_ANSI}, LEncoding{$ENDIF});
                DoneWithPostStream(AContext, LRequestInfo); // don't need the PostStream anymore
              end;
            end;

            // glue together parameters passed in the URL and those
            //
            // RLebeau: should we really be doing this?  For a GET, it might
            // makes sense to do, but for a POST the FormParams is the content
            // and the QueryParams belongs to the URL only, not the content.
            // We should be keeping everything separate for accuracy...
            LRequestInfo.UnparsedParams := LRequestInfo.FormParams;
            if Length(LRequestInfo.QueryParams) > 0 then begin
              if Length(LRequestInfo.UnparsedParams) = 0 then begin
                LRequestInfo.FUnparsedParams := LRequestInfo.QueryParams;
              end else begin
                LRequestInfo.FUnparsedParams := LRequestInfo.UnparsedParams + '&'  {Do not Localize}
                 + LRequestInfo.QueryParams;
              end;
            end;

            // Parse Params
            if ParseParams then begin
              if TextIsSame(LContentType, ContentTypeFormUrlencoded) then begin
                LRequestInfo.DecodeAndSetParams(LRequestInfo.UnparsedParams);
              end else begin
                // Parse only query params when content type is not 'application/x-www-form-urlencoded'    {Do not Localize}
                LRequestInfo.DecodeAndSetParams(LRequestInfo.QueryParams);
              end;
            end;

            // Cookies
            ReadCookiesFromRequestHeader;

            // Authentication
            s := LRequestInfo.RawHeaders.Values['Authorization'];    {Do not Localize}
            if Length(s) > 0 then begin
              LAuthType := Fetch(s, ' ');
              LRequestInfo.FAuthExists := DoParseAuthentication(AContext, LAuthType, s, LRequestInfo.FAuthUsername, LRequestInfo.FAuthPassword);
              if not LRequestInfo.FAuthExists then begin
                raise EIdHTTPUnsupportedAuthorisationScheme.Create(
                 RSHTTPUnsupportedAuthorisationScheme);
              end;
            end;

            // Session management
            GetSessionFromCookie(AContext, LRequestInfo, LResponseInfo, LContinueProcessing);
            if LContinueProcessing then begin
              try
                // These essentially all "retrieve" so they are all "Get"s
                if LRequestInfo.CommandType in [hcGET, hcPOST, hcHEAD] then begin
                  DoCommandGet(AContext, LRequestInfo, LResponseInfo);
                end else begin
                  DoCommandOther(AContext, LRequestInfo, LResponseInfo);
                end;
              except
                on E: EIdSocketError do begin // don't stop socket exceptions
                  raise;
                end;
                on E: Exception do begin
                  LResponseInfo.ResponseNo := 500;
                  LResponseInfo.ContentText := E.Message;
                  DoCommandError(AContext, LRequestInfo, LResponseInfo, E);
                end;
              end;
            end;

            // Write even though WriteContent will, may be a redirect or other
            if not LResponseInfo.HeaderHasBeenWritten then begin
              LResponseInfo.WriteHeader;
            end;
            // Always check ContentText first
            if (Length(LResponseInfo.ContentText) > 0)
             or Assigned(LResponseInfo.ContentStream) then begin
              LResponseInfo.WriteContent;
            end;
          finally
            LCloseConnection := LResponseInfo.CloseConnection;
            FreeAndNil(LResponseInfo);
          end;
        finally
          FreeAndNil(LRequestInfo);
        end;
      until LCloseConnection;
    except
      on E: EIdSocketError do begin
        if not ((E.LastError = Id_WSAESHUTDOWN) or (E.LastError = Id_WSAECONNABORTED) or (E.LastError = Id_WSAECONNRESET)) then begin
          raise;
        end;
      end;
      on E: EIdClosedSocket do begin
        AContext.Connection.Disconnect;
      end;
    end;
  finally
    AContext.Connection.Disconnect(False);
  end;
end;

end.

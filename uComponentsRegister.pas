unit uComponentsRegister;

interface

uses System.Classes, uVvIdHttpServer;

procedure Register;

implementation

procedure register;
begin
  RegisterComponents('VV Components', [TIdHttpServerExt]);
end;

end.

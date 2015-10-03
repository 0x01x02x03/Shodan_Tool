// Shodan Tool 0.6
// (C) Doddy Hackman 2015

unit tool;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.ComCtrls, IdBaseComponent,
  IdComponent, IdTCPConnection, IdTCPClient, IdHTTP, Vcl.StdCtrls, IdSSLOpenSSL,
  IdIOHandler, IdIOHandlerSocket, IdIOHandlerStack, IdSSL, uLkJSON, PerlRegex,
  Clipbrd, Vcl.Imaging.pngimage, Vcl.ExtCtrls, ShellApi;

type
  TForm1 = class(TForm)
    StatusBar1: TStatusBar;
    PageControl1: TPageControl;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;
    nave: TIdHTTP;
    TabSheet3: TTabSheet;
    TabSheet4: TTabSheet;
    GroupBox1: TGroupBox;
    ip: TEdit;
    Button1: TButton;
    GroupBox2: TGroupBox;
    console1: TMemo;
    ssl: TIdSSLIOHandlerSocketOpenSSL;
    GroupBox3: TGroupBox;
    query: TEdit;
    Button2: TButton;
    GroupBox4: TGroupBox;
    console2: TMemo;
    GroupBox5: TGroupBox;
    target: TEdit;
    Button3: TButton;
    GroupBox6: TGroupBox;
    console3: TMemo;
    GroupBox7: TGroupBox;
    query2: TEdit;
    Button4: TButton;
    GroupBox8: TGroupBox;
    console4: TMemo;
    TabSheet5: TTabSheet;
    GroupBox9: TGroupBox;
    query3: TEdit;
    Button5: TButton;
    GroupBox10: TGroupBox;
    console5: TMemo;
    TabSheet6: TTabSheet;
    GroupBox11: TGroupBox;
    console6: TMemo;
    Button6: TButton;
    TabSheet7: TTabSheet;
    GroupBox12: TGroupBox;
    console7: TMemo;
    Button7: TButton;
    TabSheet8: TTabSheet;
    GroupBox13: TGroupBox;
    host: TEdit;
    result1: TEdit;
    Button8: TButton;
    GroupBox14: TGroupBox;
    reverse_ip: TEdit;
    result2: TEdit;
    Button9: TButton;
    GroupBox15: TGroupBox;
    getmyip: TEdit;
    Button10: TButton;
    Button11: TButton;
    TabSheet9: TTabSheet;
    GroupBox16: TGroupBox;
    console8: TMemo;
    Button12: TButton;
    Image1: TImage;
    TabSheet10: TTabSheet;
    GroupBox17: TGroupBox;
    Image2: TImage;
    Label1: TLabel;
    procedure Button1Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button3Click(Sender: TObject);
    procedure Button4Click(Sender: TObject);
    procedure Button5Click(Sender: TObject);
    procedure Button6Click(Sender: TObject);
    procedure Button7Click(Sender: TObject);
    procedure Button8Click(Sender: TObject);
    procedure Button9Click(Sender: TObject);
    procedure Button11Click(Sender: TObject);
    procedure Button10Click(Sender: TObject);
    procedure Button12Click(Sender: TObject);
    procedure console1DblClick(Sender: TObject);
    procedure console2DblClick(Sender: TObject);
    procedure console3DblClick(Sender: TObject);
    procedure console4DblClick(Sender: TObject);
    procedure console5DblClick(Sender: TObject);
    procedure console6DblClick(Sender: TObject);
    procedure console7DblClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;
  api_key: string;

implementation

{$R *.dfm}

procedure TForm1.FormCreate(Sender: TObject);
var
  dir: string;
begin
  api_key := ''; // Your API Key
  dir := 'logs';
  if not(DirectoryExists(dir)) then
  begin
    CreateDir(dir);
  end;
  ChDir(dir);
end;

procedure TForm1.Button1Click(Sender: TObject);
var
  code: string;

var
  json, json2: TlkJSONobject;
  i: integer;

var
  ip_found, country_found, country_code, region_name, postal_code: string;

var
  ip_str, product, version, data, cpe, timestamp, last_update, port, os, isp,
    ans, banner: string;

begin

  StatusBar1.Panels[0].Text := '[+] Searching ...';
  Form1.StatusBar1.Update;

  code := nave.Get('https://api.shodan.io/shodan/host/' + ip.Text + '?key='
    + api_key);

  console1.Lines.Clear();

  json := TlkJSON.ParseText(code) as TlkJSONobject;

  if not(json.Field['ip'] = nil) then
  begin
    if not(json.Field['ip'].SelfTypeName = 'jsNull') then
    begin
      ip_found := json.Field['ip'].Value;
    end;
  end;
  if not(json.Field['country_name'] = nil) then
  begin
    if not(json.Field['country_name'].SelfTypeName = 'jsNull') then
    begin
      country_found := json.Field['country_name'].Value;
    end;
  end;
  if not(json.Field['country_code'] = nil) then
  begin
    if not(json.Field['country_code'].SelfTypeName = 'jsNull') then
    begin
      country_code := json.Field['country_code'].Value;
    end;
  end;
  if not(json.Field['region_name'] = nil) then
  begin
    if not(json.Field['region_name'].SelfTypeName = 'jsNull') then
    begin
      region_name := json.Field['region_name'].Value;
    end;
  end;
  if not(json.Field['postal_code'] = nil) then
  begin
    if not(json.Field['postal_code'].SelfTypeName = 'jsNull') then
    begin
      postal_code := json.Field['postal_code'].Value;
    end;
  end;

  console1.Lines.Add('[+] IP : ' + ip_found);
  console1.Lines.Add('[+] Country : ' + country_found);
  console1.Lines.Add('[+] Country Code : ' + country_code);
  console1.Lines.Add('[+] Region Name : ' + region_name);
  console1.Lines.Add('[+] Postal Code : ' + postal_code + sLineBreak);

  for i := 0 to json.Field['data'].Count - 1 do
  begin
    console1.Lines.Add('------------------------------------');
    json2 := (json.Field['data'].Child[i] as TlkJSONobject);

    if not(json2.Field['ip_str'] = nil) then
    begin
      if not(json2.Field['ip_str'].SelfTypeName = 'jsNull') then
      begin
        ip_str := json2.Field['ip_str'].Value;
      end;
    end;

    if not(json2.Field['product'] = nil) then
    begin
      if not(json2.Field['product'].SelfTypeName = 'jsNull') then
      begin
        product := json2.Field['product'].Value;
      end;
    end;

    if not(json2.Field['version'] = nil) then
    begin
      if not(json2.Field['version'].SelfTypeName = 'jsNull') then
      begin
        version := json2.Field['version'].Value;
      end;
    end;

    if not(json2.Field['data'] = nil) then
    begin
      if not(json2.Field['data'].SelfTypeName = 'jsNull') then
      begin
        data := json2.Field['data'].Value;
      end;
    end;

    if not(json2.Field['cpe'].SelfTypeName = 'jsNull') then
    begin
      cpe := json2.Field['cpe'].Value;
    end;

    if not(json2.Field['timestamp'] = nil) then
    begin
      if not(json2.Field['timestamp'].SelfTypeName = 'jsNull') then
      begin
        timestamp := json2.Field['timestamp'].Value;
      end;
    end;

    if not(json2.Field['last_update'] = nil) then
    begin
      if not(json2.Field['last_update'].SelfTypeName = 'jsNull') then
      begin
        last_update := json2.Field['last_update'].Value;
      end;
    end;

    if not(json2.Field['port'] = nil) then
    begin
      if not(json2.Field['port'].SelfTypeName = 'jsNull') then
      begin
        port := json2.Field['port'].Value;
      end;
    end;

    if not(json2.Field['os'] = nil) then
    begin
      if not(json2.Field['os'].SelfTypeName = 'jsNull') then
      begin
        os := json2.Field['os'].Value;
      end;
    end;

    if not(json2.Field['isp'] = nil) then
    begin
      if not(json2.Field['isp'].SelfTypeName = 'jsNull') then
      begin
        isp := json2.Field['isp'].Value;
      end;
    end;

    if not(json2.Field['ans'] = nil) then
    begin
      if not(json2.Field['ans'].SelfTypeName = 'jsNull') then
      begin
        ans := json2.Field['ans'].Value;
      end;
    end;

    if not(json2.Field['banner'] = nil) then
    begin
      if not(json2.Field['banner'].SelfTypeName = 'jsNull') then
      begin
        banner := json2.Field['banner'].Value;
      end;
    end;

    console1.Lines.Add('[+] IP : ' + ip_str);
    console1.Lines.Add('[+] Product : ' + product);
    console1.Lines.Add('[+] Version : ' + version);
    console1.Lines.Add('[+] Data : ' + data);
    console1.Lines.Add('[+] CPE : ' + cpe);
    console1.Lines.Add('[+] Timestamp : ' + timestamp);
    console1.Lines.Add('[+] Last_update : ' + last_update);
    console1.Lines.Add('[+] OS : ' + os);
    console1.Lines.Add('[+] ISP : ' + isp);
    console1.Lines.Add('[+] ANS : ' + ans);
    console1.Lines.Add('[+] Banner : ' + banner + sLineBreak);

    console1.Lines.Add('------------------------------------' + sLineBreak);

  end;

  StatusBar1.Panels[0].Text := '[+] Finished';
  Form1.StatusBar1.Update;

end;

procedure TForm1.Button2Click(Sender: TObject);
var
  code, facets: string;
  json: TlkJSONobject;
  total: string;

begin
  console2.Clear();
  facets := '';

  StatusBar1.Panels[0].Text := '[+] Searching ...';
  Form1.StatusBar1.Update;

  code := nave.Get('https://api.shodan.io/shodan/host/count?key=' + api_key +
    '&query=' + query.Text + '&facets=' + facets);

  json := TlkJSON.ParseText(code) as TlkJSONobject;

  if not(json.Field['total'] = nil) then
  begin
    if not(json.Field['total'].SelfTypeName = 'jsNull') then
    begin
      total := json.Field['total'].Value;
    end;
  end;

  console2.Lines.Add('[+] Total : ' + total);

  StatusBar1.Panels[0].Text := '[+] Finished';
  Form1.StatusBar1.Update;

end;

procedure TForm1.Button3Click(Sender: TObject);
var
  code: string;

var
  json, json2: TlkJSONobject;
  i: integer;

var
  total, ip_found, country_found, country_code, region_name,
    postal_code: string;

var
  ip_str, product, version, data, cpe, timestamp, last_update, port, os, isp,
    ans, banner: string;

begin

  StatusBar1.Panels[0].Text := '[+] Searching ...';
  Form1.StatusBar1.Update;

  code := nave.Get('https://api.shodan.io/shodan/host/search?key=' + api_key +
    '&query=' + target.Text + '&facets=');

  console3.Lines.Clear();

  json := TlkJSON.ParseText(code) as TlkJSONobject;

  //

  if not(json.Field['total'] = nil) then
  begin
    if not(json.Field['total'].SelfTypeName = 'jsNull') then
    begin
      total := json.Field['total'].Value;
    end;
  end;

  if not(json.Field['ip_str'] = nil) then
  begin
    if not(json.Field['ip_str'].SelfTypeName = 'jsNull') then
    begin
      ip_found := json.Field['ip_str'].Value;
    end;
  end;
  if not(json.Field['country_name'] = nil) then
  begin
    if not(json.Field['country_name'].SelfTypeName = 'jsNull') then
    begin
      country_found := json.Field['country_name'].Value;
    end;
  end;
  if not(json.Field['country_code'] = nil) then
  begin
    if not(json.Field['country_code'].SelfTypeName = 'jsNull') then
    begin
      country_code := json.Field['country_code'].Value;
    end;
  end;
  if not(json.Field['region_name'] = nil) then
  begin
    if not(json.Field['region_name'].SelfTypeName = 'jsNull') then
    begin
      region_name := json.Field['region_name'].Value;
    end;
  end;
  if not(json.Field['postal_code'] = nil) then
  begin
    if not(json.Field['postal_code'].SelfTypeName = 'jsNull') then
    begin
      postal_code := json.Field['postal_code'].Value;
    end;
  end;

  console1.Lines.Add('[+] Total : ' + total + sLineBreak);
  console1.Lines.Add('[+] IP : ' + ip_found);
  console1.Lines.Add('[+] Country : ' + country_found);
  console1.Lines.Add('[+] Country Code : ' + country_code);
  console1.Lines.Add('[+] Region Name : ' + region_name);
  console1.Lines.Add('[+] Postal Code : ' + postal_code + sLineBreak);


  //

  for i := 0 to json.Field['matches'].Count - 1 do
  begin
    console3.Lines.Add('------------------------------------');
    json2 := (json.Field['matches'].Child[i] as TlkJSONobject);

    if not(json2.Field['ip_str'] = nil) then
    begin
      if not(json2.Field['ip_str'].SelfTypeName = 'jsNull') then
      begin
        ip_str := json2.Field['ip_str'].Value;
      end;
    end;

    if not(json2.Field['product'] = nil) then
    begin
      if not(json2.Field['product'].SelfTypeName = 'jsNull') then
      begin
        product := json2.Field['product'].Value;
      end;
    end;

    if not(json2.Field['version'] = nil) then
    begin
      if not(json2.Field['version'].SelfTypeName = 'jsNull') then
      begin
        version := json2.Field['version'].Value;
      end;
    end;

    if not(json2.Field['data'] = nil) then
    begin
      if not(json2.Field['data'].SelfTypeName = 'jsNull') then
      begin
        data := json2.Field['data'].Value;
      end;
    end;

    if not(json2.Field['timestamp'] = nil) then
    begin
      if not(json2.Field['timestamp'].SelfTypeName = 'jsNull') then
      begin
        timestamp := json2.Field['timestamp'].Value;
      end;
    end;

    if not(json2.Field['last_update'] = nil) then
    begin
      if not(json2.Field['last_update'].SelfTypeName = 'jsNull') then
      begin
        last_update := json2.Field['last_update'].Value;
      end;
    end;

    if not(json2.Field['port'] = nil) then
    begin
      if not(json2.Field['port'].SelfTypeName = 'jsNull') then
      begin
        port := json2.Field['port'].Value;
      end;
    end;

    if not(json2.Field['os'] = nil) then
    begin
      if not(json2.Field['os'].SelfTypeName = 'jsNull') then
      begin
        os := json2.Field['os'].Value;
      end;
    end;

    if not(json2.Field['isp'] = nil) then
    begin
      if not(json2.Field['isp'].SelfTypeName = 'jsNull') then
      begin
        isp := json2.Field['isp'].Value;
      end;
    end;

    if not(json2.Field['ans'] = nil) then
    begin
      if not(json2.Field['ans'].SelfTypeName = 'jsNull') then
      begin
        ans := json2.Field['ans'].Value;
      end;
    end;

    if not(json2.Field['banner'] = nil) then
    begin
      if not(json2.Field['banner'].SelfTypeName = 'jsNull') then
      begin
        banner := json2.Field['banner'].Value;
      end;
    end;

    console3.Lines.Add('[+] IP : ' + ip_str);
    console3.Lines.Add('[+] Product : ' + product);
    console3.Lines.Add('[+] Version : ' + version);
    console3.Lines.Add('[+] Data : ' + data);
    console3.Lines.Add('[+] Timestamp : ' + timestamp);
    console3.Lines.Add('[+] Last_update : ' + last_update);
    console3.Lines.Add('[+] OS : ' + os);
    console3.Lines.Add('[+] ISP : ' + isp);
    console3.Lines.Add('[+] ANS : ' + ans);
    console3.Lines.Add('[+] Banner : ' + banner + sLineBreak);

    console3.Lines.Add('------------------------------------' + sLineBreak);

    StatusBar1.Panels[0].Text := '[+] Finished';
    Form1.StatusBar1.Update;

  end;
end;

procedure TForm1.Button4Click(Sender: TObject);
var
  code: string;

var
  json, json2: TlkJSONobject;
  i: integer;

var
  total, votes, description, title, timestamp, query_found: string;

begin

  StatusBar1.Panels[0].Text := '[+] Searching ...';
  Form1.StatusBar1.Update;

  code := nave.Get('https://api.shodan.io/shodan/query?key=' + api_key);

  console4.Lines.Clear();

  json := TlkJSON.ParseText(code) as TlkJSONobject;

  if not(json.Field['total'] = nil) then
  begin
    if not(json.Field['total'].SelfTypeName = 'jsNull') then
    begin
      total := json.Field['total'].Value;
    end;
  end;

  console4.Lines.Add('[+] Total : ' + total + sLineBreak);

  for i := 0 to json.Field['matches'].Count - 1 do
  begin

    json2 := (json.Field['matches'].Child[i] as TlkJSONobject);

    if not(json2.Field['votes'] = nil) then
    begin
      if not(json2.Field['votes'].SelfTypeName = 'jsNull') then
      begin
        votes := json2.Field['votes'].Value;
      end;
    end;

    if not(json2.Field['description'] = nil) then
    begin
      if not(json2.Field['description'].SelfTypeName = 'jsNull') then
      begin
        description := json2.Field['description'].Value;
      end;
    end;

    if not(json2.Field['title'] = nil) then
    begin
      if not(json2.Field['title'].SelfTypeName = 'jsNull') then
      begin
        title := json2.Field['title'].Value;
      end;
    end;

    if not(json2.Field['timestamp'] = nil) then
    begin
      if not(json2.Field['timestamp'].SelfTypeName = 'jsNull') then
      begin
        timestamp := json2.Field['timestamp'].Value;
      end;
    end;

    if not(json2.Field['query'] = nil) then
    begin
      if not(json2.Field['query'].SelfTypeName = 'jsNull') then
      begin
        query_found := json2.Field['query'].Value;
      end;
    end;

    console4.Lines.Add('[+] Votes : ' + votes);
    console4.Lines.Add('[+] Description : ' + description);
    console4.Lines.Add('[+] Title : ' + title);
    console4.Lines.Add('[+] Timestamp :' + timestamp);
    console4.Lines.Add('[+] Query : ' + query_found + sLineBreak);

    StatusBar1.Panels[0].Text := '[+] Finished';
    Form1.StatusBar1.Update;

  end;

end;

procedure TForm1.Button5Click(Sender: TObject);
var
  code: string;

var
  json, json2: TlkJSONobject;
  i: integer;

var
  total, votes, description, title, timestamp, query_found: string;

begin

  StatusBar1.Panels[0].Text := '[+] Searching ...';
  Form1.StatusBar1.Update;

  code := nave.Get('https://api.shodan.io/shodan/query/search?key=' + api_key +
    '&query=' + query3.Text);

  console5.Lines.Clear();

  json := TlkJSON.ParseText(code) as TlkJSONobject;

  if not(json.Field['total'] = nil) then
  begin
    if not(json.Field['total'].SelfTypeName = 'jsNull') then
    begin
      total := json.Field['total'].Value;
    end;
  end;

  console5.Lines.Add('[+] Total : ' + total + sLineBreak);

  for i := 0 to json.Field['matches'].Count - 1 do
  begin

    json2 := (json.Field['matches'].Child[i] as TlkJSONobject);

    if not(json2.Field['votes'] = nil) then
    begin
      if not(json2.Field['votes'].SelfTypeName = 'jsNull') then
      begin
        votes := json2.Field['votes'].Value;
      end;
    end;

    if not(json2.Field['description'] = nil) then
    begin
      if not(json2.Field['description'].SelfTypeName = 'jsNull') then
      begin
        description := json2.Field['description'].Value;
      end;
    end;

    if not(json2.Field['title'] = nil) then
    begin
      if not(json2.Field['title'].SelfTypeName = 'jsNull') then
      begin
        title := json2.Field['title'].Value;
      end;
    end;

    if not(json2.Field['timestamp'] = nil) then
    begin
      if not(json2.Field['timestamp'].SelfTypeName = 'jsNull') then
      begin
        timestamp := json2.Field['timestamp'].Value;
      end;
    end;

    if not(json2.Field['query'] = nil) then
    begin
      if not(json2.Field['query'].SelfTypeName = 'jsNull') then
      begin
        query_found := json2.Field['query'].Value;
      end;
    end;

    console5.Lines.Add('[+] Votes : ' + votes);
    console5.Lines.Add('[+] Description : ' + description);
    console5.Lines.Add('[+] Title : ' + title);
    console5.Lines.Add('[+] Timestamp :' + timestamp);
    console5.Lines.Add('[+] Query : ' + query_found + sLineBreak);

    StatusBar1.Panels[0].Text := '[+] Finished';
    Form1.StatusBar1.Update;

  end;
end;

procedure TForm1.Button6Click(Sender: TObject);
var
  code: string;

var
  json, json2: TlkJSONobject;
  i: integer;

var
  Value, Count, total: string;

begin

  StatusBar1.Panels[0].Text := '[+] Searching ...';
  Form1.StatusBar1.Update;

  code := nave.Get('https://api.shodan.io/shodan/query/tags?key=' + api_key);

  console6.Lines.Clear();

  json := TlkJSON.ParseText(code) as TlkJSONobject;

  if not(json.Field['total'] = nil) then
  begin
    if not(json.Field['total'].SelfTypeName = 'jsNull') then
    begin
      total := json.Field['total'].Value;
    end;
  end;

  console6.Lines.Add('[+] Tags Found : ' + total + sLineBreak);

  for i := 0 to json.Field['matches'].Count - 1 do
  begin

    json2 := (json.Field['matches'].Child[i] as TlkJSONobject);

    if not(json2.Field['value'] = nil) then
    begin
      if not(json2.Field['value'].SelfTypeName = 'jsNull') then
      begin
        Value := json2.Field['value'].Value;
      end;
    end;

    if not(json2.Field['count'] = nil) then
    begin
      if not(json2.Field['count'].SelfTypeName = 'jsNull') then
      begin
        Count := json2.Field['count'].Value;
      end;
    end;

    console6.Lines.Add('[+] Value : ' + Value);
    console6.Lines.Add('[+] Count : ' + Count + sLineBreak);

  end;

  StatusBar1.Panels[0].Text := '[+] Finished';
  Form1.StatusBar1.Update;

end;

procedure TForm1.Button7Click(Sender: TObject);
var
  Regex: TPerlRegEx;
  code: string;
begin

  StatusBar1.Panels[0].Text := '[+] Searching ...';
  Form1.StatusBar1.Update;

  code := nave.Get('https://api.shodan.io/shodan/services?key=' + api_key);

  console7.Lines.Clear();

  Regex := TPerlRegEx.Create();
  Regex.Regex := '"(.*?)": "(.*?)"';
  Regex.Options := [preCaseless, preMultiLine];
  Regex.Subject := code;

  while Regex.MatchAgain do
  begin
    console7.Lines.Add('[+] Port : ' + Regex.Groups[1]);
    console7.Lines.Add('[+] Name : ' + Regex.Groups[2] + sLineBreak);
  end;

  StatusBar1.Panels[0].Text := '[+] Finished';
  Form1.StatusBar1.Update;

end;

procedure TForm1.Button8Click(Sender: TObject);
var
  code: string;
  Regex: TPerlRegEx;
begin

  StatusBar1.Panels[0].Text := '[+] Getting IP ...';
  Form1.StatusBar1.Update;

  code := nave.Get('https://api.shodan.io/dns/resolve?hostnames=' + host.Text +
    '&key=' + api_key);

  Regex := TPerlRegEx.Create();
  Regex.Regex := '"(.*?)": "(.*?)"';
  Regex.Options := [preCaseless, preMultiLine];
  Regex.Subject := code;

  if Regex.Match then
  begin
    result1.Text := Regex.Groups[2];
  end;

  StatusBar1.Panels[0].Text := '[+] Finished';
  Form1.StatusBar1.Update;

end;

procedure TForm1.Button9Click(Sender: TObject);
var
  code: string;
  Regex: TPerlRegEx;
begin

  StatusBar1.Panels[0].Text := '[+] Getting Host ...';
  Form1.StatusBar1.Update;

  code := nave.Get('https://api.shodan.io/dns/reverse?ips=' + reverse_ip.Text +
    '&key=' + api_key);

  Regex := TPerlRegEx.Create();
  Regex.Regex := '"(.*?)": \["(.*?)"\]';
  Regex.Options := [preCaseless, preMultiLine];
  Regex.Subject := code;

  if Regex.Match then
  begin
    result2.Text := Regex.Groups[2];
  end;

  StatusBar1.Panels[0].Text := '[+] Finished';
  Form1.StatusBar1.Update;
end;

procedure TForm1.console1DblClick(Sender: TObject);
var
  nombre: string;
begin
  nombre := ip.Text + '.txt';
  if (FileExists(nombre)) then
  begin
    DeleteFile(nombre);
  end;
  console1.Lines.SaveToFile(nombre);
  ShellExecute(0, 'open', PChar(GetCurrentDir + '/' + nombre), nil, nil,
    SW_SHOWNORMAL);
end;

procedure TForm1.console2DblClick(Sender: TObject);
var
  nombre: string;
begin
  nombre := query.Text + '.txt';
  if (FileExists(nombre)) then
  begin
    DeleteFile(nombre);
  end;
  console2.Lines.SaveToFile(nombre);
  ShellExecute(0, 'open', PChar(GetCurrentDir + '/' + nombre), nil, nil,
    SW_SHOWNORMAL);
end;

procedure TForm1.console3DblClick(Sender: TObject);
var
  nombre: string;
begin
  nombre := target.Text + '.txt';
  if (FileExists(nombre)) then
  begin
    DeleteFile(nombre);
  end;
  console3.Lines.SaveToFile(nombre);
  ShellExecute(0, 'open', PChar(GetCurrentDir + '/' + nombre), nil, nil,
    SW_SHOWNORMAL);
end;

procedure TForm1.console4DblClick(Sender: TObject);
var
  nombre: string;
begin
  nombre := query2.Text + '.txt';
  if (FileExists(nombre)) then
  begin
    DeleteFile(nombre);
  end;
  console4.Lines.SaveToFile(nombre);
  ShellExecute(0, 'open', PChar(GetCurrentDir + '/' + nombre), nil, nil,
    SW_SHOWNORMAL);

end;

procedure TForm1.console5DblClick(Sender: TObject);
var
  nombre: string;
begin
  nombre := query3.Text + '.txt';
  if (FileExists(nombre)) then
  begin
    DeleteFile(nombre);
  end;
  console5.Lines.SaveToFile(nombre);
  ShellExecute(0, 'open', PChar(GetCurrentDir + '/' + nombre), nil, nil,
    SW_SHOWNORMAL);
end;

procedure TForm1.console6DblClick(Sender: TObject);
var
  nombre: string;
begin
  nombre := 'tags' + '.txt';
  if (FileExists(nombre)) then
  begin
    DeleteFile(nombre);
  end;
  console6.Lines.SaveToFile(nombre);
  ShellExecute(0, 'open', PChar(GetCurrentDir + '/' + nombre), nil, nil,
    SW_SHOWNORMAL);
end;

procedure TForm1.console7DblClick(Sender: TObject);
var
  nombre: string;
begin
  nombre := 'services' + '.txt';
  if (FileExists(nombre)) then
  begin
    DeleteFile(nombre);
  end;
  console7.Lines.SaveToFile(nombre);
  ShellExecute(0, 'open', PChar(GetCurrentDir + '/' + nombre), nil, nil,
    SW_SHOWNORMAL);
end;

procedure TForm1.Button11Click(Sender: TObject);
var
  code: string;
  Regex: TPerlRegEx;
begin

  StatusBar1.Panels[0].Text := '[+] Getting IP ...';
  Form1.StatusBar1.Update;

  code := nave.Get('https://api.shodan.io/tools/myip?key=' + api_key);

  Regex := TPerlRegEx.Create();
  Regex.Regex := '"(.*)"';
  Regex.Options := [preCaseless, preMultiLine];
  Regex.Subject := code;

  if Regex.Match then
  begin
    getmyip.Text := Regex.Groups[1];
  end;

  StatusBar1.Panels[0].Text := '[+] Finished';
  Form1.StatusBar1.Update;

end;

procedure TForm1.Button10Click(Sender: TObject);
begin
  Clipboard().AsText := getmyip.Text;
end;

procedure TForm1.Button12Click(Sender: TObject);
var
  code: string;
  unlocked_left, telnet, plan, https, unlocked: string;

var
  json, json2: TlkJSONobject;
  i: integer;

begin

  StatusBar1.Panels[0].Text := '[+] Searching ...';
  Form1.StatusBar1.Update;

  code := nave.Get('https://api.shodan.io/api-info?key=' + api_key);

  console8.Lines.Clear();

  json := TlkJSON.ParseText(code) as TlkJSONobject;

  if not(json.Field['unlocked_left'] = nil) then
  begin
    if not(json.Field['unlocked_left'].SelfTypeName = 'jsNull') then
    begin
      unlocked_left := json.Field['unlocked_left'].Value;
    end;
  end;

  if not(json.Field['telnet'] = nil) then
  begin
    if not(json.Field['telnet'].SelfTypeName = 'jsNull') then
    begin
      telnet := json.Field['telnet'].Value;
    end;
  end;

  if not(json.Field['plan'] = nil) then
  begin
    if not(json.Field['plan'].SelfTypeName = 'jsNull') then
    begin
      plan := json.Field['plan'].Value;
    end;
  end;

  if not(json.Field['https'] = nil) then
  begin
    if not(json.Field['https'].SelfTypeName = 'jsNull') then
    begin
      https := json.Field['https'].Value;
    end;
  end;

  if not(json.Field['unlocked'] = nil) then
  begin
    if not(json.Field['unlocked'].SelfTypeName = 'jsNull') then
    begin
      unlocked := json.Field['unlocked'].Value;
    end;
  end;

  console8.Lines.Add('[+] Unlocked Left : ' + unlocked_left);
  console8.Lines.Add('[+] Telnet : ' + telnet);
  console8.Lines.Add('[+] Plan : ' + plan);
  console8.Lines.Add('[+] HTTPS : ' + https);
  console8.Lines.Add('[+] Unlocked : ' + unlocked);

  StatusBar1.Panels[0].Text := '[+] Finished';
  Form1.StatusBar1.Update;

end;

end.

// The End ?

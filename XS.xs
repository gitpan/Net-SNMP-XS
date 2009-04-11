#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

// C99 required

//#define BENCHMARK

#define ASN_BOOLEAN           0x01
#define ASN_INTEGER32         0x02
#define ASN_OCTET_STRING      0x04
#define ASN_NULL              0x05
#define ASN_OBJECT_IDENTIFIER 0x06
#define ASN_SEQUENCE          0x30
#define ASN_IPADDRESS         0x40
#define ASN_COUNTER32         0x41
#define ASN_UNSIGNED32        0x42
#define ASN_TIMETICKS         0x43
#define ASN_OPAQUE            0x44
#define ASN_COUNTER64         0x46

#define MAX_OID_STRLEN 4096

static SV *msg;
static int errflag, leading_dot;
static U8 *buf, *cur;
static STRLEN len, rem;

static SV *
x_get_cv (SV *cb_sv)
{
  HV *st;
  GV *gvp;
  CV *cv = sv_2cv (cb_sv, &st, &gvp, 0);

  if (!cv)
    croak ("CODE reference expected");

  return (SV *)cv;
}

static void
error (const char *errmsg)
{
  errflag = 1;

  if (!msg)
    croak ("Net::SNMP::XS fatal error, parser called without parsing context");

  dSP;
  PUSHMARK (SP);
  EXTEND (SP, 2);
  PUSHs (msg);
  PUSHs (sv_2mortal (newSVpv (errmsg, 0)));
  PUTBACK;
  call_method ("_error", G_VOID | G_DISCARD);
}

static int
need (int count)
{
  if (count < 0 || (int)rem < count)
    {
      error ("Unexpected end of message buffer");
      return 0;
    }

  return 1;
}

static U8 *
getn (int count, const U8 *errres)
{
  if (!need (count))
    return (U8 *)errres;

  U8 *res = cur;

  cur += count;
  rem -= count;

  return res;
}

static U8
get8 (void)
{
  if (rem <= 0)
    {
      error ("Unexpected end of message buffer");
      return 0;
    }

  rem--;
  return *cur++;
}

static U32
getb (void)
{
  U32 res = 0;

  for (;;)
    {
      U8 c = get8 ();
      res = (res << 7) | (c & 0x7f);

      if (!(c & 0x80))
        return res;
    }
}

#ifdef BENCHMARK
static double t1;

static double
tstamp (void)
{
  struct timeval tv;
  gettimeofday (&tv, 0);
  return tv.tv_sec + tv.tv_usec * 0.000001;
}
#endif

static U32
process_length (void)
{
  U32 res = get8 ();

  if (res & 0x80)
    {
      int cnt = res & 0x7f;
      res = 0;

      switch (cnt)
        {
          case 0:
            error ("Indefinite ASN.1 lengths not supported");
            return 0;

          default:
            error ("ASN.1 length too long");
            return 0;

          case 4: res = (res << 8) | get8 ();
          case 3: res = (res << 8) | get8 ();
          case 2: res = (res << 8) | get8 ();
          case 1: res = (res << 8) | get8 ();
        }
    }

  return res;
}

static U32
process_integer32 (void)
{
  U32 length = process_length ();

  if (length <= 0)
    {
      error ("INTEGER32 length equal to zero");
      return 0;
    }

  U8 *data = getn (length, 0);

  if (!data)
    return 0;

  if (length > 5 || (length > 4 && data [0]))
    {
      error ("INTEGER32 length too long");
      return 0;
    }

  U32 res = data [0] & 0x80 ? 0xffffffff : 0;

  while (length--)
    res = (res << 8) | *data++;

  return res;
}

static SV *
process_integer32_sv (void)
{
  return newSViv ((I32)process_integer32 ());
}

static SV *
process_unsigned32_sv (void)
{
  return newSVuv ((U32)process_integer32 ());
}

#if IVSIZE >= 8

static U64TYPE
process_integer64 (void)
{
  U32 length = process_length ();

  if (length <= 0)
    {
      error ("INTEGER64 length equal to zero");
      return 0;
    }

  U8 *data = getn (length, 0);

  if (!data)
    return 0;

  if (length > 9 || (length > 8 && data [0]))
    {
      error ("INTEGER64 length too long");
      return 0;
    }

  U64TYPE res = data [0] & 0x80 ? 0xffffffffffffffff : 0;

  while (length--)
    res = (res << 8) | *data++;

  return res;
}

static SV *
process_integer64_sv (void)
{
  return newSViv ((I64TYPE)process_integer64 ());
}

static SV *
process_unsigned64_sv (void)
{
  return newSVuv ((U64TYPE)process_integer64 ());
}

#endif

static SV *
process_octet_string_sv (void)
{
  U32 length = process_length ();

  U8 *data = getn (length, 0);
  if (!data)
    {
      error ("OCTET STRING too long");
      return &PL_sv_undef;
    }

  return newSVpvn (data, length);
}

static char *
write_uv (char *buf, U32 u)
{
  // the one-digit case is absolutely predominant
  if (u < 10)
    *buf++ = u + '0';
  else
    buf += sprintf (buf, "%u", (unsigned int)u);

  return buf;
}

static SV *
process_object_identifier_sv (void)
{
  U32 length = process_length ();

  if (length <= 0)
    {
      error ("OBJECT IDENTIFIER length equal to zero");
      return &PL_sv_undef;
    }

  U8 *end = cur + length;
  U32 w = getb ();

  static char oid[MAX_OID_STRLEN]; // must be static
  char *app = oid;

  *app = '.'; app += ! ! leading_dot;
  app = write_uv (app, (U8)w / 40);
  *app++ = '.';
  app = write_uv (app, (U8)w % 40);

  // we assume an oid component is never > 64 bytes
  while (cur < end && oid + sizeof (oid) - app > 64)
    {
      w = getb ();
      *app++ = '.';
      app = write_uv (app, w);
    }

  return newSVpvn (oid, app - oid);
}

static AV *av_type;

static SV *
process_sv (int *found)
{
  int type = get8 ();

  *found = type;

  SV *res;

  switch (type)
    {
      case ASN_OBJECT_IDENTIFIER:
        res = process_object_identifier_sv ();
        break;

      case ASN_INTEGER32:
        res = process_integer32_sv ();
        break;

      case ASN_UNSIGNED32:
      case ASN_COUNTER32:
      case ASN_TIMETICKS:
        res = process_unsigned32_sv ();
        break;

      case ASN_SEQUENCE:
        res = newSVuv (process_length ());
        break;

      case ASN_OCTET_STRING:
      case ASN_OPAQUE:
        res = process_octet_string_sv ();
        break;

      default:
        {
          if (type > AvFILLp (av_type) || !SvTYPE (AvARRAY (av_type)[type]) == SVt_PVCV)
            {
              error ("Unknown ASN.1 type");
              return &PL_sv_undef;
            }

          dSP;
          PUSHMARK (SP);
          EXTEND (SP, 2);
          PUSHs (msg);
          PUSHs (sv_2mortal (newSViv (type)));
          PUTBACK;
          int count = call_sv (AvARRAY (av_type)[type], G_SCALAR);
          SPAGAIN;
          res = count ? SvREFCNT_inc (TOPs) : &PL_sv_undef;
        }
    }

  return errflag ? &PL_sv_undef : res;
}

MODULE = Net::SNMP::XS		PACKAGE = Net::SNMP::XS

PROTOTYPES: ENABLE

BOOT:
	av_type = newAV ();

void
set_type (int type, SV *cv)
	CODE:
        av_store (av_type, type, SvREFCNT_inc (x_get_cv (cv)));

void
set_msg (SV *msg_, SV *buf_)
	CODE:
{
        if (msg)
          croak ("recursive invocation of Net::SNMP::XS parser is not supported");

        errflag     = 0;
        leading_dot = -1;
        msg         = SvREFCNT_inc (msg_);
        buf         = SvPVbyte (buf_, len);
        cur         = buf;
        rem         = len;
#ifdef BENCHMARK
        t1          = tstamp ();
#endif
}

void
clr_msg ()
	CODE:
        SvREFCNT_dec (msg); msg = 0;
        buf = cur = (U8 *)"";
        len = rem = 0;
#ifdef BENCHMARK
        printf ("%f\n", tstamp () - t1);//D
#endif

MODULE = Net::SNMP::XS		PACKAGE = Net::SNMP::Message

void
_buffer_get (SV *self, int count = -1)
	PPCODE:
{
	// grrr.
	if (count < 0)
          {
            hv_delete ((HV *)SvRV (self), "_index" , 6, G_DISCARD);
            hv_delete ((HV *)SvRV (self), "_length", 7, G_DISCARD);
            SV **svp = hv_fetch ((HV *)SvRV (self), "_buffer", 7, 1);
            XPUSHs (sv_2mortal (newSVsv (*svp)));
            sv_setpvn (*svp, "", 0);
            XSRETURN (1);
          }

        char *data = getn (count, 0);

        if (data)
          XPUSHs (sv_2mortal (newSVpvn (data, count)));
}

U32
index (SV *self, int ndx = -1)
	CODE:
{
        if (ndx >= 0 && ndx < len)
          {
            cur = buf + ndx;
            rem = len - ndx;
          }

        RETVAL = cur - buf;
}
	OUTPUT:
        RETVAL

U32
_process_length (SV *self, ...)
	ALIAS:
        _process_sequence = 0
	CODE:
        RETVAL = process_length ();
	OUTPUT:
        RETVAL

SV *
_process_integer32 (SV *self, ...)
	CODE:
        RETVAL = process_integer32_sv ();
	OUTPUT:
        RETVAL

SV *
_process_counter (SV *self, ...)
	ALIAS:
        _process_gauge     = 0
        _process_timeticks = 0
	CODE:
        RETVAL = process_unsigned32_sv ();
	OUTPUT:
        RETVAL

#if IVSIZE >= 8

SV *
_process_counter64 (SV *self, ...)
	CODE:
        RETVAL = process_unsigned64_sv ();
	OUTPUT:
        RETVAL

#endif

SV *
_process_object_identifier (SV *self, ...)
	CODE:
        RETVAL = process_object_identifier_sv ();
	OUTPUT:
        RETVAL

SV *
_process_octet_string (SV *self, ...)
	ALIAS:
        _process_opaque = 0
	CODE:
        RETVAL = process_octet_string_sv ();
	OUTPUT:
        RETVAL

SV *
_process_ipaddress (SV *self, ...)
	CODE:
{
  	U32 length = process_length ();
        if (length != 4)
          {
            error ("IP ADDRESS length not four");
            XSRETURN_UNDEF;
          }

        U8 *data = getn (4, "\x00\x00\x00\x00");
        RETVAL = newSVpvf ("%d.%d.%d.%d", data [0], data [1], data [2], data [3]);
}
	OUTPUT:
        RETVAL

SV *
process (SV *self, SV *expected = &PL_sv_undef, SV *found = 0)
	CODE:
{
  	int type;

        RETVAL = process_sv (&type);

        if (found)
          sv_setiv (found, type);

        if (SvOK (expected) && type != SvIV (expected))
          error ("Expected a different type than found");
}
	OUTPUT:
        RETVAL

MODULE = Net::SNMP::XS		PACKAGE = Net::SNMP::PDU

SV *
_process_var_bind_list (SV *self)
        CODE:
{
        if (get8 () != ASN_SEQUENCE)
          error ("SEQUENCE expected at beginning of VarBindList");
        int seqlen = process_length ();
        U8 *end = cur + seqlen;

        HV *list  = newHV ();
        AV *names = newAV ();
        HV *types = newHV ();

        hv_store ((HV *)SvRV (self), "_var_bind_list" , sizeof ("_var_bind_list" ) - 1, newRV_noinc ((SV *)list ), 0);
        hv_store ((HV *)SvRV (self), "_var_bind_names", sizeof ("_var_bind_names") - 1, newRV_noinc ((SV *)names), 0);
        hv_store ((HV *)SvRV (self), "_var_bind_types", sizeof ("_var_bind_types") - 1, newRV_noinc ((SV *)types), 0);
        
        while (cur < end && !errflag)
          {
            // SEQUENCE ObjectName ObjectSyntax
            if (get8 () != ASN_SEQUENCE)
              error ("SEQUENCE expected at beginning of VarBind");
            process_length ();

            if (get8 () != ASN_OBJECT_IDENTIFIER)
              error ("OBJECT IDENTIFIER expected at beginning of VarBind");
            int type, oidlen;
            SV *oid = process_object_identifier_sv ();
            SV *val = process_sv (&type);
        
            hv_store_ent (types, oid, newSViv (type), 0);
            hv_store_ent (list , oid, val, 0);
            av_push (names, oid);
          }
        
        //return $this->_report_pdu_error if ($this->{_pdu_type} == REPORT);
        
        RETVAL = newRV_inc ((SV *)list);
}
	OUTPUT:
        RETVAL



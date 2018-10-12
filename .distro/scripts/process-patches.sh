SCRIPTS=$1
shift
NAME=$1
shift
VERSION=$1
shift
RELEASE=$1
shift
DATE=$1
shift
COMMIT=$1
shift
TARBALL=$1
shift
TARURL=$1
shift
SPECNAME=$1
shift
MARKER=$1
shift
LOCALVERSION=$1
shift
ZRELEASE=$1
shift
RCVERSION=$1
shift
CLANG=$1
shift

SOURCES=rpmbuild/SOURCES
SRPMDIR=rpmbuild/SRPM
SPEC=rpmbuild/SPECS/${SPECNAME}

LOCAL_PYTHON=$(
  if python3 --version > /dev/null; then
    echo python3
  elif python --version > /dev/null; then
    echo python
  fi 2> /dev/null
)

if [ -z "$LOCAL_PYTHON" ]; then
  echo "No python interpreter found"
  exit 1
fi
echo "Using $LOCAL_PYTHON"

# Pre-cleaning
rm -rf .tmp psection patchlist

echo ${TARBALL} / ${TARURL}
if [ ! -f ${TARBALL} ]; then
   wget ${TARURL}
fi
cp ${TARBALL} ${SOURCES}/${TARBALL}

if [ -n "${ZRELEASE}" ]; then
   ZRELEASE=.${ZRELEASE}
fi

if [ -n "${RCVERSION}" ]; then
   RCVERSION="%global rcver ${RCVERSION}"
fi

# Handle patches
git format-patch --first-parent --no-renames -k --no-binary --ignore-submodules ${MARKER}.. > patchlist
for patchfile in `cat patchlist`; do
  ${LOCAL_PYTHON} ${SCRIPTS}/frh.py ${patchfile} > .tmp
  if grep -q '^diff --git ' .tmp; then
    num=$(echo $patchfile | sed 's/\([0-9]*\).*/\1/')
    echo "Patch${num}: ${patchfile}" >> psection
    mv .tmp ${SOURCES}/${patchfile}
  fi
done

# Handle spec file
cp ${SPECNAME}.template ${SPEC}

sed -i -e "/%%PATCHLIST%%/r psection
           /%%PATCHLIST%%/d
           s/%%CLANG%%/${CLANG}/
           s/%%VERSION%%/${VERSION}/
           s/%%RELEASE%%/${RELEASE}/
           s/%%ZRELEASE%%/${ZRELEASE}/
           s/%%RCVERSION%%/${RCVERSION}/
           s/%%DATE%%/${DATE}/
           s/%%COMMIT%%/${COMMIT}/
           s/%%LOCALVERSION%%/${LOCALVERSION}/" ${SPEC}

# Final cleaning
rm -rf `cat patchlist`
rm -rf .tmp psection patchlist

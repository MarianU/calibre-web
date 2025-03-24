/**
 * waits until queue is finished, meaning the book is done loading
 * @param callback
 */
function qFinished(callback){
    let timeout=setInterval(()=>{
        if(reader.rendition.q.running===undefined)
            clearInterval(timeout);
            callback();
        },300
    )
}

function calculateProgress(){
    let data=reader.rendition.location?.end;
    return Math.round(epub.locations.percentageFromCfi(data?.cfi)*100);
}

// register new event emitter locationchange that fires on urlchange
// source: https://stackoverflow.com/a/52809105/21941129
(() => {
    let oldPushState = history.pushState;
    history.pushState = function pushState() {
        let ret = oldPushState.apply(this, arguments);
        window.dispatchEvent(new Event('locationchange'));
        return ret;
    };

    let oldReplaceState = history.replaceState;
    history.replaceState = function replaceState() {
        let ret = oldReplaceState.apply(this, arguments);
        window.dispatchEvent(new Event('locationchange'));
        return ret;
    };

    window.addEventListener('popstate', () => {
        window.dispatchEvent(new Event('locationchange'));
    });
})();

window.addEventListener('locationchange',()=>{
    let newPos=calculateProgress();
    progressDiv.textContent=newPos+"%";
});

var epub=ePub(calibre.bookUrl)

let progressDiv=document.getElementById("progress");

qFinished(()=>{
    epub.locations.generate().then(()=> {
    window.dispatchEvent(new Event('locationchange'))
});
})

oldEPUBJSSaveSettings = EPUBJS.Reader.prototype.saveSettings;

var previousStoredLocationCfi = "";

EPUBJS.Reader.prototype.saveSettings = function() {
    currentCfi = this.book && this.rendition.currentLocation().start.cfi || "";
    if (previousStoredLocationCfi === currentCfi) {
        return;
    }

    var csrftoken = $("input[name='csrf_token']").val();
    previousStoredLocationCfi = currentCfi;

    let data=reader.rendition.location?.end;
    $.ajax(calibre.lastReadPositionUrl, {
        method: "post",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify({
            previousLocationCfi: currentCfi || "",
            progress: epub.locations.percentageFromCfi(data?.cfi)
        }),
        headers: { "X-CSRFToken": csrftoken }
    })
    .fail(function (xhr, status, error) {
        alert(error);
    });

    oldEPUBJSSaveSettings.call(reader);
}

// store reading possition every 5 minutes
let interval = setInterval(function () {
    EPUBJS.Reader.prototype.saveSettings.call(reader);
}, 5 * 60 * 1000);

if (calibre.lastReadPosition !== '') {
    setTimeout(function() {
        previousStoredLocationCfi = calibre.lastReadPosition;
        reader.selectedRange(calibre.lastReadPosition);
        reader.hashChanged();
    }, 5000);
}
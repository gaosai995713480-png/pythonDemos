import{C as e,I as t,M as n,N as r,P as i,S as a,_ as o,d as s,g as c,i as l,k as u,m as d,t as f,v as p,w as m,x as h,y as g}from"./_plugin-vue_export-helper-CtQ9_G5O.js";import"./ThemeSwitcher-DBIKyjH-.js";import{t as _}from"./TopBar-ClXMAO20.js";var v={class:`letter-nav`},y=[`onClick`],b={class:`letter-wrap`},x={class:`letter-date`},S={class:`letter-salutation`},C={class:`letter-body`},w={key:0,class:`cursor`},T=f({__name:`LetterView`,setup(f){let T=l(),E=[{title:`第一封信`,date:`写于心动的那一天`,salutation:`亲爱的路路：`,body:`你好呀，是我。

当你看到这封信的时候，我可能正在某个角落里偷偷想你。

还记得我们第一次见面吗？那天的阳光刚刚好，你笑起来的样子像极了春天里最温柔的风。从那一刻起，我的世界就多了一种颜色——是你的颜色。

我不太会说那些甜到腻的情话，但我想让你知道：

遇见你之前，我从来不知道"心动"是什么感觉。
遇见你之后，我才明白，原来一个人对另一个人的喜欢，可以是一瞬间的事，也可以是一辈子的事。

你的每一个表情我都想好好记住。
你开心的时候，我的整个世界都在发光。
你难过的时候，我恨不得把所有温柔都给你。

谢谢你出现在我的生命里。
谢谢你让平凡的日子变得值得期待。
谢谢你成为我心里最柔软的那个角落。

往后的日子，我想慢慢地、认真地，和你一起走。无论是阳光灿烂的日子，还是风雨交加的夜晚，我都想站在你身边，做你最坚定的依靠。`,sign:`永远为你心动的人`},{title:`给未来的你`,date:`写于某个想你的深夜`,salutation:`致最特别的你：`,body:`夜深了，窗外的月光很温柔，像你的眼睛。

今天突然很想你，想你笑起来嘴角弯弯的样子，想你撒娇时故意嘟嘴的模样，想你认真做事时专注的侧脸。

你知道吗？

和你在一起的每一天，我都觉得自己是这个世界上最幸运的人。

有人说喜欢是一阵风，来得快也去得快。
可是我对你的喜欢，像是种在心里的树。
每一天都在生长，每一天都更加枝繁叶茂。

我想象过很多关于未来的画面：

我们一起去看海，让浪花打湿你的裙摆。
我们一起走过四季，春天赏花、夏天听蝉、秋天踩落叶、冬天围炉吃火锅。
我们一起变老，即使满头白发也要手牵手散步。

这些画面里，每一帧都有你。

所以，请你也要好好的。
好好吃饭，好好睡觉，好好笑。
因为你好了，我的全世界就都好了。`,sign:`最爱你的人`},{title:`生日快乐`,date:`写于你的专属日子`,salutation:`我最珍贵的宝贝：`,body:`今天是你的生日，是这个世界上最重要的日子。

因为这一天，你来到了这个世界。
因为你来到了这个世界，我才有了遇见你的可能。
因为遇见了你，我的人生才有了心动的故事。

所以今天，我要对全世界说：
谢谢这个世界送给我的最好的礼物——你。

生日快乐，我的女孩。

愿你的每一个愿望都能实现。
愿你永远被温柔以待。
愿你的笑容永远灿烂如花。
愿你的眼里永远有星星。

而我会做那个，
永远站在你身后为你鼓掌的人，
永远在你需要时第一个出现的人，
永远把你放在心尖最柔软的地方的人。

今天你是小公主，
以后的每一天你也是。

我爱你，不止在今天。`,sign:`你的专属守护者`}],D=n(0),O=n(``),k=n(!0),A=n(!1),j=null,M=null;function N(){if(!M)try{M=new(window.AudioContext||window.webkitAudioContext)}catch{return}let e=M.createOscillator(),t=M.createGain();e.type=`sine`,e.frequency.setValueAtTime(600+Math.random()*400,M.currentTime),t.gain.setValueAtTime(.03,M.currentTime),t.gain.exponentialRampToValueAtTime(.001,M.currentTime+.05),e.connect(t),t.connect(M.destination),e.start(M.currentTime),e.stop(M.currentTime+.05)}function P(e){j&&=(clearTimeout(j),null),D.value=e;let t=E[e];O.value=``,A.value=!1,k.value=!0;let n=t.body,r=0;function i(){if(r>=n.length){k.value=!1,A.value=!0;return}let e=n[r];O.value+=e,e.trim()&&N(),r++;let t=55;`，。！？、；：`.includes(e)?t=300:`。！？`.includes(e)?t=500:e===`
`&&(t=200),j=setTimeout(i,t)}j=setTimeout(i,500)}return h(()=>P(0)),a(()=>{j&&clearTimeout(j)}),(n,a)=>(e(),o(s,null,[g(_,{title:`💌 表白信`,onBack:a[1]||=e=>r(T).push(`/`)},{default:u(()=>[d(`button`,{class:`btn-ghost replay-btn`,onClick:a[0]||=e=>P(D.value)},`重新播放 ↻`)]),_:1}),d(`div`,v,[(e(),o(s,null,m(E,(e,n)=>d(`button`,{key:n,class:i([`letter-tab`,{"is-active":D.value===n}]),onClick:e=>P(n)},t(e.title),11,y)),64))]),d(`div`,b,[a[2]||=d(`div`,{class:`letter-seal`},`💕`,-1),d(`div`,x,t(E[D.value].date),1),d(`div`,S,t(E[D.value].salutation),1),d(`div`,C,[p(t(O.value),1),k.value?(e(),o(`span`,w)):c(``,!0)]),d(`div`,{class:i([`letter-sign`,{"is-visible":A.value}])},`— `+t(E[D.value].sign),3)])],64))}},[[`__scopeId`,`data-v-eaa1b3a6`]]);export{T as default};
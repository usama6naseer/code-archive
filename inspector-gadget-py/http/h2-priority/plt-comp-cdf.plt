set datafile separator ","
set terminal postscript eps enhanced color font 'Helvetica,28' linewidth 2 rounded
#set size 0.9,0.8

set style line 81 lc rgb "#808080" lt 0 lw 1 dt 3
set grid back ls 81 lw 0.5
set border 3 back ls 80

set xtics border in scale 1,0.5 nomirror norotate autojustify
set ytics border in scale 1,0.5 nomirror norotate autojustify
set xtics nomirror
set ytics nomirror
set tics in
set mxtics 10
#set xtics 1
#set ytics 20

#set title font ", 12"
#set title "Critical parameters in configuration"
#set xlabel font ", 16"
set xlabel "% improvement in PLT"
#set ylabel font ", 16"
set ylabel "CDF of pageloads" offset 1,0


set xtics font ", 20"
set ytics font ", 20"
#set xtics rotate by 30 right
#set key outside
set key font ", 24"
set key bottom right

#set xrange [0:4.5]
#set yrange [0:0.999]

set linetype 1 lc rgb '#1E90FF'
set linetype 2 lc rgb '#EEE8AA'
set linetype 3 lc rgb '#B22222'
set linetype 4 lc rgb '#2E8B57'
set linetype 6 lc rgb '#DAA520'
set linetype 5 lc rgb 'black' linewidth 0.5

set output "plt-comp-cdf.eps"

plot "plt-comp-cdf.csv" using 2:4 with line title "Best vs No priority" linewidth 5 lc 7, \
"plt-comp-cdf.csv" using 3:4 with line title "Best vs Worst" linewidth 5 lc 1, \
"plt-comp-cdf.csv" using 5:4 with line title "Best vs nghttp" linewidth 5 lc 6, \
"plt-comp-cdf.csv" using 6:4 with line title "Best vs firefox" linewidth 5 lc 4





